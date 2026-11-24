#!/usr/bin/env python3
"""Cloudflare-only ingress wrapper: preflight, plan, apply-patch, verify, undo.

Wraps scripts/ingress-switch.py (run as a subprocess, unmodified). Network access is
read-only and sits behind injectable clients (Cloudflare GET reads, HTTPS probes).
This script never calls Phala, holds no Phala credential and never executes the Phala
port_policy PATCH: apply-patch and undo only EMIT the exact command and payload for an
authorized operator. See docs/runbooks/cf-only-ingress.md.
"""
import argparse
from collections import namedtuple
from datetime import datetime, timezone
import errno
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import re
import shlex
import socket
import ssl
import subprocess
import sys
import tempfile
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from uuid import UUID

SWITCH = Path(__file__).with_name("ingress-switch.py")
PUBLIC_HOST = "node.tinycloud.xyz"
TEE_HOST = "tee.node.tinycloud.xyz"
TUNNEL_SERVICE = "http://tinycloud:8000"
DEFAULT_WORKER = "tinycloud-tee-proxy"
MANAGEMENT_PORT = 10022
GATEWAY_SUFFIXES = ("8000", "8000g", "443", "443s", "443g")
LABEL = "operator evidence from automated reads, not a cryptographic attestation"
ORIGIN_ATTESTATION = ("operator-attested, NOT verified: the Worker's ORIGIN_URL is a secret whose value the Cloudflare "
                      "API never returns; it is recorded as the --tunnel-host the operator says the set-origin step received")
CONNECTOR_BASIS = "tunnel status healthy with active connections and none pending reconnect, as read from the Cloudflare API"
END_TO_END_SHOWS = ("node.tinycloud.xyz answers /info with the recorded node id while every probed gateway path shows a "
                    "positive refusal, so the Worker reaches the node by some route other than the closed gateway")
END_TO_END_CANNOT = ["that the secret equals the tunnel host (another independent origin serving the same node would "
                     "also pass)", "that no unprobed gateway host or address is used", "anything before the restriction: "
                     "while the gateway is open the secret may still point at it and node.* would also pass"]
# Closed means a POSITIVE refusal: a connect error (refused), a reset, or no route. Anything that completes TLS or
# HTTP is open or unknown, and both fail verify. There is no operator-extensible allow-list.
CLOSED_SIGNALS = ("tcp_refused", "tcp_reset", "no_route")
CLOUDFLARE_TOKEN_ENV = "CLOUDFLARE_READ_TOKEN"
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX32 = re.compile(r"[0-9a-f]{32}")
SCRIPT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}")
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,63}")
LABEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,40}")
Clients = namedtuple("Clients", "http cf")


class Refusal(ValueError):
    """A refusal; messages are static text, never values read from the network."""


class ClientError(Exception):
    """A read failed; carries a static message only."""


def require(condition, message):
    if not condition:
        raise Refusal(message)


def fingerprint(value):
    return hashlib.sha256(str(value).encode()).hexdigest()[:12]


def utcnow():
    return datetime.now(timezone.utc)


def write_private(path, value):
    """Exclusive 0600 creation; never replaces an existing file."""
    with open(path, "x", encoding="utf-8", opener=lambda p, f: os.open(p, f, 0o600)) as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def require_new_path(path, what):
    p = Path(path)
    require(not p.exists() and not p.is_symlink(), f"{what} must be a new path")
    require(p.resolve().parent.is_dir() and os.access(p.resolve().parent, os.W_OK), f"{what} parent directory is not writable")


def private_file(path, what):
    p = Path(path)
    require(p.is_file() and not p.is_symlink(), f"{what} must be an existing regular file")
    st = p.stat()
    require(st.st_mode & 0o077 == 0 and st.st_uid == os.getuid(), f"{what} must be owner-only (0600)")
    return p


def validate_cloudflare_ids(account_id, zone_id, script=None):
    """Values are interpolated into API URL paths: strict shapes only."""
    require(isinstance(account_id, str) and HEX32.fullmatch(account_id), "Account id must be 32 hex characters")
    require(isinstance(zone_id, str) and HEX32.fullmatch(zone_id), "Zone id must be 32 hex characters")
    if script is not None:
        require(isinstance(script, str) and SCRIPT_RE.fullmatch(script), "Invalid Worker script name")


# ---------------------------------------------------------------- real read-only clients
# Never run against the network by this change; unit tests exercise them with fakes and a
# localhost server only.

class CloudflareReader:
    """GET-only Cloudflare API reads. The token never appears in any message."""
    API = "https://api.cloudflare.com/client/v4"

    def __init__(self, token, account_id, zone_id, opener=urlopen):
        validate_cloudflare_ids(account_id, zone_id)
        self.token, self.account, self.zone, self.opener = token, account_id, zone_id, opener

    def _get(self, path):
        request = Request(self.API + path, method="GET", headers={"Authorization": "Bearer " + self.token})
        try:
            with self.opener(request, timeout=15) as response:
                body = response.read(4_000_000)
        except HTTPError as error:
            raise ClientError(f"Cloudflare read failed: HTTP {error.code}") from None
        except (URLError, OSError):
            raise ClientError("Cloudflare read failed: network error") from None
        try:
            data = json.loads(body)
        except ValueError:
            raise ClientError("Cloudflare read failed: invalid response") from None
        if not isinstance(data, dict) or data.get("success") is not True:
            raise ClientError("Cloudflare read failed: unsuccessful response")
        return data.get("result")

    def tunnel(self, tunnel_id):
        return self._get(f"/accounts/{self.account}/cfd_tunnel/{tunnel_id}")

    def tunnel_ingress(self, tunnel_id):
        result = self._get(f"/accounts/{self.account}/cfd_tunnel/{tunnel_id}/configurations")
        return ((result or {}).get("config") or {}).get("ingress")

    def dns_records(self, name):
        return self._get(f"/zones/{self.zone}/dns_records?name={name}")

    def worker(self, script):
        validate_cloudflare_ids(self.account, self.zone, script)
        base = f"/accounts/{self.account}/workers/scripts/{script}"
        # INFERENCE: the active deployment is the newest by created_on and a single 100% version is live.
        listed = ((self._get(base + "/deployments") or {}).get("deployments")) or []
        deployments = sorted((d for d in listed if isinstance(d, dict)), key=lambda d: str(d.get("created_on", "")),
                             reverse=True)
        versions = (deployments[0].get("versions") if deployments else None) or []
        version = versions[0].get("version_id") if len(versions) == 1 and isinstance(versions[0], dict) \
            and versions[0].get("percentage") == 100 else None
        kind = None
        if isinstance(version, str) and VERSION_RE.fullmatch(version):
            # INFERENCE: the version's own bindings (resources.bindings), not the script-level /settings, which
            # may reflect an uploaded-but-not-deployed version. Exactly one ORIGIN_URL; the API returns only its
            # name and type, never a secret value. Absent or duplicated -> None.
            detail = self._get(f"{base}/versions/{version}")
            bindings = [b for b in ((detail or {}).get("resources") or {}).get("bindings") or []
                        if isinstance(b, dict) and b.get("name") == "ORIGIN_URL"]
            kind = bindings[0].get("type") if len(bindings) == 1 else None
        else:
            version = None
        routes = self._get(f"/zones/{self.zone}/workers/routes") or []
        return {"version_id": version, "origin_binding": kind if isinstance(kind, str) else None,
                "routes": [{"pattern": r.get("pattern"), "script": r.get("script")} for r in routes if isinstance(r, dict)]}


class NetworkProbe:
    """HTTPS /info reads and fresh-connection probes from this host only (one vantage).

    Every probe reports a distinct signal token, never a bare "closed": tcp_refused, tcp_reset,
    tls_rejected, closed_after_tls, http_<status>, http_200_unparsed, malformed_http, node_info,
    ssh_banner, non_ssh_data, timeout, no_address, error. The caller decides which are acceptable.
    """
    FAMILIES = {"ipv4": socket.AF_INET, "ipv6": socket.AF_INET6}

    def __init__(self, timeout=8):
        self.timeout = timeout

    def info(self, host):
        try:
            with urlopen(Request(f"https://{host}/info"), timeout=15) as response:
                status, body = response.status, response.read(1_000_000)
        except HTTPError as error:
            return {"status": error.code, "node_id": None}
        except (URLError, OSError):
            return {"status": None, "node_id": None}
        return {"status": status, "node_id": self._node_id(body)}

    @staticmethod
    def _node_id(body):
        try:
            value = json.loads(body).get("nodeId")
        except (ValueError, AttributeError):
            return None
        return value if isinstance(value, str) and value else None

    def _addresses(self, host, port, family):
        try:
            return [i[4] for i in socket.getaddrinfo(host, port, self.FAMILIES[family], socket.SOCK_STREAM)]
        except socket.gaierror:
            return []

    def _attempt(self, address, host, banner):
        """One connection attempt -> (signal, node_id or None)."""
        try:
            raw = socket.create_connection(address[:2], timeout=self.timeout)
        except (socket.timeout, TimeoutError):
            return "timeout", None
        except ConnectionRefusedError:
            return "tcp_refused", None
        except ConnectionError:
            return "tcp_reset", None
        except OSError as error:
            return ("no_route" if error.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH) else "error"), None
        with raw:
            context = ssl.create_default_context()
            context.check_hostname, context.verify_mode = False, ssl.CERT_NONE  # reachability only
            try:
                stream = context.wrap_socket(raw, server_hostname=host)
            except (socket.timeout, TimeoutError):
                return "timeout", None
            except (ssl.SSLError, EOFError):
                return "tls_rejected", None
            except ConnectionError:
                return "tcp_reset", None
            except OSError:
                return "error", None
            with stream:
                try:
                    if banner:
                        data = stream.recv(255)
                        if not data:
                            return "closed_after_tls", None
                        return ("ssh_banner" if data.startswith(b"SSH-2.0-") else "non_ssh_data"), None
                    stream.sendall(f"GET /info HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
                    response = http.client.HTTPResponse(stream, method="GET")
                    response.begin()
                    body = response.read(65536)  # de-chunks and honours Content-Length
                except (socket.timeout, TimeoutError):
                    return "timeout", None
                except (http.client.RemoteDisconnected, ssl.SSLEOFError, EOFError):
                    return "closed_after_tls", None
                except (http.client.HTTPException, ValueError):
                    return "malformed_http", None
                except ssl.SSLError:
                    return "tls_rejected", None
                except ConnectionError:
                    return "tcp_reset", None
                except OSError:
                    return "error", None
        if response.status != 200:
            return f"http_{response.status}", None
        node_id = self._node_id(body)
        return ("node_info", node_id) if node_id else ("http_200_unparsed", None)

    def _run(self, host, family, port, banner):
        addresses = self._addresses(host, port, family)
        if not addresses:
            return {"outcome": "no_address", "signals": ["no_address"]}
        attempts = [self._attempt(address, host, banner) for address in addresses]
        signals = [signal for signal, _ in attempts]
        result = {"signals": signals, "outcome": signals[0] if len(set(signals)) == 1 else "mixed"}
        for signal, node_id in attempts:
            if signal == "node_info":
                return {"outcome": "node_info", "signals": signals, "node_id": node_id}
        return result

    def probe(self, host, family, port=443):
        """Fresh HTTPS /info request with SNI/Host `host` -> {'outcome', 'signals', 'node_id'?}"""
        return self._run(host, family, port, banner=False)

    def mgmt_probe(self, host, family="ipv4", port=443):
        """INFERENCE: management is reached through the gateway TLS route <app>-10022.<gw>:443; 'open' means an
        SSH-2.0 banner is read after the TLS handshake. -> {'outcome', 'signals'}"""
        return self._run(host, family, port, banner=True)


# ---------------------------------------------------------------- preflight

def host_name(value, what):
    require(isinstance(value, str) and re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+", value),
            f"Invalid {what} hostname")
    return value


def check_tunnel_host(host):
    host_name(host, "tunnel")
    require(host not in {PUBLIC_HOST, TEE_HOST} and not host.endswith((".phala.network", ".cfargotunnel.com")),
            "Tunnel host must be an independent tunnel hostname, not the public or Phala gateway")


def preflight(cfg, clients, now):
    """Build the origin receipt from real reads; refuse on any mismatch or missing evidence."""
    require(HEX40.fullmatch(cfg["app_id"]), "Expected a 40-hex app ID")
    try:
        UUID(cfg["tunnel_id"])
    except ValueError:
        raise Refusal("Tunnel id is not a UUID") from None
    validate_cloudflare_ids(cfg["account_id"], cfg["zone_id"], cfg["worker_script"])
    host = cfg["tunnel_host"]
    check_tunnel_host(host)
    http, cf = clients.http, clients.cf

    tunnel = cf.tunnel(cfg["tunnel_id"])
    require(isinstance(tunnel, dict) and tunnel.get("id") == cfg["tunnel_id"] and not tunnel.get("deleted_at"),
            "Cloudflare tunnel read does not match the expected tunnel")
    connections = tunnel.get("connections")
    require(tunnel.get("status") == "healthy" and isinstance(connections, list) and connections
            and all(isinstance(c, dict) and not c.get("is_pending_reconnect") for c in connections),
            "Tunnel connector is not healthy with active connections")

    ingress = cf.tunnel_ingress(cfg["tunnel_id"])
    require(isinstance(ingress, list), "Tunnel ingress could not be read")
    # First match wins in cloudflared: the first rule for the host must be the plain one, and no catch-all may precede it.
    first = next((r for r in ingress if isinstance(r, dict) and (r.get("hostname") == host or not r.get("hostname"))), None)
    require(first is not None and first.get("hostname") == host and first.get("service") == TUNNEL_SERVICE
            and not first.get("path"), "Tunnel ingress does not route the tunnel hostname to the node service")

    records = cf.dns_records(host)
    require(isinstance(records, list) and len(records) == 1 and isinstance(records[0], dict)
            and records[0].get("type") == "CNAME" and records[0].get("proxied") is True
            and records[0].get("content") == f"{cfg['tunnel_id']}.cfargotunnel.com",
            "Tunnel hostname is not bound to the expected tunnel")

    worker = cf.worker(cfg["worker_script"])
    require(isinstance(worker, dict) and isinstance(worker.get("version_id"), str) and worker["version_id"],
            "Worker version could not be read")
    # The Cloudflare API never returns a secret's value: only the deployed version's binding name/type can be read.
    require(worker.get("origin_binding") != "plain_text",
            "Worker ORIGIN_URL is a plain_text variable; the approved path is a secret, redeploy it as a secret")
    require(worker.get("origin_binding") == "secret_text",
            "Worker has no single secret_text ORIGIN_URL binding")
    require(cfg.get("attested_origin") is True,
            "Pass --attest-origin-is-tunnel-host: the secret's value cannot be read, so the operator must attest it")
    if cfg.get("expect_worker_version"):
        require(worker["version_id"] == cfg["expect_worker_version"], "Worker version differs from the expected version")
    routes = [r for r in worker.get("routes") or [] if isinstance(r, dict)]
    require(any(r.get("pattern") == f"{PUBLIC_HOST}/*" and r.get("script") == cfg["worker_script"] for r in routes),
            "node.tinycloud.xyz is not routed to the Worker")
    require(all(r.get("script") == cfg["worker_script"] for r in routes
                if str(r.get("pattern", "")).startswith(f"{PUBLIC_HOST}/")),
            "A route for node.tinycloud.xyz points at another script")

    origin, public = http.info(host), http.info(PUBLIC_HOST)
    require(origin.get("status") == 200 and public.get("status") == 200, "/info is not healthy on both routes")
    require(origin.get("node_id") and origin.get("node_id") == public.get("node_id"),
            "Node ids differ or are missing between the tunnel host and node.tinycloud.xyz")
    return {"app_id": cfg["app_id"], "public_url": f"https://{PUBLIC_HOST}", "worker_origin": f"https://{host}",
            "tunnel_hostname": host, "tunnel_id": cfg["tunnel_id"], "verified_at_utc": now.isoformat(),
            "connector_authenticated": True, "connector_authenticated_basis": CONNECTOR_BASIS,
            "origin_status": 200, "public_status": 200,
            "origin_node_id": origin["node_id"], "public_node_id": public["node_id"],
            "worker_version_id": worker["version_id"], "worker_origin_binding": "secret_text",
            "worker_origin_value": ORIGIN_ATTESTATION, "tunnel_connections": len(connections),
            "evidence_label": LABEL}


def summarize(receipt):
    """Receipt fields safe to print: node ids appear only as short fingerprints."""
    keys = ("app_id", "worker_origin", "tunnel_id", "worker_version_id", "worker_origin_binding",
            "tunnel_connections", "verified_at_utc")
    return dict({k: receipt[k] for k in keys}, node_id_fingerprint=fingerprint(receipt["origin_node_id"]),
                connector_authenticated_basis=CONNECTOR_BASIS, worker_origin_value=ORIGIN_ATTESTATION,
                evidence_label=LABEL)


# ---------------------------------------------------------------- switch wrapper / plan

def run_switch(argv):
    result = subprocess.run([sys.executable, str(SWITCH), *map(str, argv)], text=True, capture_output=True)
    if result.returncode != 0:
        raise Refusal("The local ingress switch refused: " + (result.stderr.strip().splitlines() or ["no detail"])[0])
    return json.loads(result.stdout)


def stage(a, receipt, apply):
    with tempfile.TemporaryDirectory(prefix="ingress-cf-only-") as tmp:
        proof = Path(tmp) / "verified-origin.json"
        write_private(proof, receipt)
        return run_switch(["--compose", a.compose, "--target", a.target, "--expect-app-id", a.expect_app_id,
                           "--network", a.network, "--verified-origin", proof, "--snapshot", a.snapshot,
                           "--apply" if apply else "--dry-run"])


def plan_hash(a, receipt, switch_plan):
    material = {"v": 1, "app_id": a.expect_app_id, "cvm_id": switch_plan["cvm_id"],
                "compose_sha256": hashlib.sha256(Path(a.compose).read_bytes()).hexdigest(),
                "tunnel_id": receipt["tunnel_id"], "worker_origin": receipt["worker_origin"],
                "worker_version_id": receipt["worker_version_id"],
                "node_id_sha256": hashlib.sha256(receipt["origin_node_id"].encode()).hexdigest(),
                "before": switch_plan["before"], "after": switch_plan["after"], "patch": switch_plan["patch"],
                "snapshot": str(Path(a.snapshot).resolve())}
    return hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def undo_patch(before):
    return {"compose": {"port_policy": before["value"] if before["present"] else None}}


def build_plan(a, clients, now):
    receipt = preflight(cfg_of(a), clients, now)
    switch_plan = stage(a, receipt, apply=False)
    digest = plan_hash(a, receipt, switch_plan)
    return receipt, switch_plan, digest


def phala_command(cvm_id, patch_file):
    return f"phala api /cvms/{shlex.quote(cvm_id)} -X PATCH --input {shlex.quote(str(patch_file))}"


def verify_command(a, expect, receipt_path):
    """Every value is shlex-quoted; a value not known yet is printed as a quoted placeholder."""
    def value(v, placeholder):
        return shlex.quote(str(v) if v else placeholder)

    return " ".join(["python3", "scripts/ingress-cf-only.py", "verify", "--expect", expect,
                     "--expect-app-id", value(a.expect_app_id, "APP-ID"), "--snapshot", value(a.snapshot, "SNAPSHOT"),
                     "--receipt", value(receipt_path, "RECEIPT"), "--tunnel-host", value(a.tunnel_host, "TUNNEL-HOST"),
                     "--instance-id", value(getattr(a, "instance_id", None), "<INSTANCE-ID>"),
                     "--gateway-domain", value(getattr(a, "gateway_domain", None), "<GATEWAY-DOMAIN>")])


def cmd_plan(a, clients, now, out):
    receipt, sw, digest = build_plan(a, clients, now)
    emit(out, {"command": "plan", "plan_hash": digest, "evidence": summarize(receipt), "cvm_id": sw["cvm_id"],
               "intended_change": {"before": sw["before"], "after": sw["after"], "patch": sw["patch"]},
               "exact_undo": {"patch": undo_patch(sw["before"]), "snapshot": str(Path(a.snapshot).resolve()),
                              "command": "ingress-cf-only.py undo (HTTP first; keep tunnel and Worker unchanged)"},
               "executed": "nothing: read-only reads and a local dry-run; no Phala call, no file changed",
               "warning": "The PATCH restarts the CVM: both HTTP paths are interrupted; no measured timings exist",
               "next": "apply-patch --confirm " + digest})


def cmd_apply_patch(a, clients, now, out):
    require(a.confirm, "--confirm <plan-hash> is required")
    # Check every output path BEFORE staging so a failure cannot leave a half-applied local state.
    for path, what in ((a.patch_out, "Patch file"), (a.receipt_out, "Receipt file"), (a.snapshot, "Snapshot")):
        require_new_path(path, what)
    receipt, sw, digest = build_plan(a, clients, now)
    require(hmac.compare_digest(a.confirm, digest), "Confirm does not match a fresh plan; rerun plan and review it")
    staged = stage(a, receipt, apply=True)
    require(staged["patch"] == sw["patch"], "Staged patch differs from the confirmed plan")
    write_private(a.patch_out, staged["patch"])
    write_private(a.receipt_out, receipt)
    emit(out, {"command": "apply-patch", "executed_by_this_script": "local staging only; NO Phala call was made",
               "phala_command_for_authorized_operator": phala_command(sw["cvm_id"], a.patch_out),
               "payload": staged["patch"], "patch_file": str(Path(a.patch_out).resolve()),
               "snapshot": str(Path(a.snapshot).resolve()), "receipt_file": str(Path(a.receipt_out).resolve()),
               "evidence": summarize(receipt),
               "warning": "Under a GO only. The PATCH restarts the CVM and interrupts both HTTP paths.",
               "then_verify": verify_command(a, "restricted", a.receipt_out),
               "verify_note": "Fill the quoted placeholders (instance id, gateway domain). verify passes only on a "
                              "positive refusal (refused, reset, no route); anything that completes TLS or HTTP fails.",
               "if_bad": "undo --snapshot " + str(Path(a.snapshot).resolve())})


def cmd_preflight(a, clients, now, out):
    if a.out:
        require_new_path(a.out, "Receipt file")
    receipt = preflight(cfg_of(a), clients, now)
    if a.out:
        write_private(a.out, receipt)
    emit(out, {"command": "preflight", "result": "pass", "receipt_file": str(Path(a.out).resolve()) if a.out else None,
               "evidence": summarize(receipt)})


def cfg_of(a):
    return {"app_id": a.expect_app_id, "tunnel_id": a.tunnel_id, "tunnel_host": a.tunnel_host,
            "account_id": a.account_id, "zone_id": a.zone_id,
            "worker_script": a.worker_script, "expect_worker_version": a.expect_worker_version,
            "attested_origin": a.attest_origin_is_tunnel_host}


# ---------------------------------------------------------------- verify

def direct_hosts(a):
    require(HEX40.fullmatch(a.expect_app_id), "Expected a 40-hex app ID")
    require(a.instance_id and LABEL_RE.fullmatch(a.instance_id), "--instance-id is required")
    gateway = host_name(a.gateway_domain, "gateway")
    hosts = [TEE_HOST]
    for ident in (a.expect_app_id, a.instance_id):
        hosts += [f"{ident}-{suffix}.{gateway}" for suffix in GATEWAY_SUFFIXES]
    hosts += [host_name(h, "extra") for h in getattr(a, "extra_host", None) or []]
    return list(dict.fromkeys(hosts))


def management_host(a):
    """INFERENCE: management is the gateway route <app>-10022.<gateway>:443 (compose comment), not a host port."""
    return f"{a.expect_app_id}-{MANAGEMENT_PORT}.{host_name(a.gateway_domain, 'gateway')}"


def management_allowed(policy):
    """INFERENCE: no policy, or restrict_mode false, leaves management reachable."""
    if not isinstance(policy, dict) or policy.get("restrict_mode") is not True:
        return True
    return any(isinstance(p, dict) and p.get("port") == MANAGEMENT_PORT for p in policy.get("ports", []))


def load_private_snapshot(path):
    snap = json.loads(private_file(path, "Snapshot").read_text(encoding="utf-8"))
    require(isinstance(snap, dict) and isinstance(snap.get("before"), dict) and "after" in snap,
            "Snapshot is not a recorded ingress policy")
    return snap


def check(name, status, detail):
    assert status in ("pass", "fail")
    return {"check": name, "status": status, "ok": status == "pass", "detail": detail}


def signals_of(result):
    return list(result.get("signals") or [result.get("outcome") or "error"])


def judge_closed(result, family=None, allow_no_aaaa=False):
    """A path that must be closed passes only on a POSITIVE refusal signal. Anything that completed TLS or HTTP is
    open or unknown and fails; so does a timeout, an error or a resolver failure."""
    signals = signals_of(result)
    if "node_info" in signals:
        return "fail", "node answered /info: " + ",".join(signals)
    if all(s in CLOSED_SIGNALS or (s == "no_address" and family == "ipv6" and allow_no_aaaa) for s in signals):
        note = ",".join(signals)
        return "pass", note + (" (explicitly accepted: no AAAA is not proof of no IPv6 path)" if "no_address" in signals else "")
    return "fail", ",".join(signals) + " is not a positive refusal (open or unknown)"


def judge_management(result, expect_open):
    signals = signals_of(result)
    if expect_open:
        if all(s == "ssh_banner" for s in signals):
            return "pass", "SSH-2.0 banner read through the gateway route"
        return "fail", "no SSH banner: " + ",".join(signals)
    if all(s in CLOSED_SIGNALS for s in signals):
        return "pass", ",".join(signals)
    return "fail", ",".join(signals) + " is not a positive refusal (open or unknown)"


def verify(a, clients, now):
    snap = load_private_snapshot(a.snapshot)
    require(snap.get("app_id") == a.expect_app_id, "Snapshot belongs to a different app")
    receipt = json.loads(private_file(a.receipt, "Receipt").read_text(encoding="utf-8"))
    require(isinstance(receipt, dict) and receipt.get("app_id") == a.expect_app_id and receipt.get("origin_node_id")
            and receipt.get("origin_node_id") == receipt.get("public_node_id"), "Receipt is missing or inconsistent")
    require(receipt.get("tunnel_hostname") == a.tunnel_host
            and (snap.get("verified_origin") or {}).get("tunnel_id") == receipt.get("tunnel_id"),
            "Receipt, snapshot and --tunnel-host do not describe the same tunnel")
    age = (now - datetime.fromisoformat(receipt["verified_at_utc"].replace("Z", "+00:00"))).total_seconds()
    require(0 <= age <= a.max_receipt_age, "Receipt is stale; rerun preflight")
    check_tunnel_host(a.tunnel_host)
    hosts, mgmt = direct_hosts(a), management_host(a)
    http = clients.http
    node = receipt["origin_node_id"]
    checks = []

    for label, name in (("tunnel host", a.tunnel_host), ("node.tinycloud.xyz", PUBLIC_HOST)):
        info = http.info(name)
        good = info.get("status") == 200 and info.get("node_id") == node
        checks.append(check(f"{label} /info healthy with the recorded node id", "pass" if good else "fail",
                            f"status={info.get('status')} node_id_matches={info.get('node_id') == node}"))

    if a.expect == "restricted":
        for name in hosts:
            for family in ("ipv4", "ipv6"):
                status, detail = judge_closed(http.probe(name, family, 443), family, a.allow_no_aaaa)
                checks.append(check(f"{name} fresh {family} connection is positively refused", status, detail))
    else:
        require(management_allowed(snap["before"].get("value")),
                "Previous policy was restrictive; restored expectations are not automated, verify by hand")
        result = http.probe(TEE_HOST, "ipv4", 443)
        good = result.get("outcome") == "node_info" and result.get("node_id") == node
        checks.append(check(f"{TEE_HOST} fresh ipv4 connection reaches the node again", "pass" if good else "fail",
                            ",".join(signals_of(result))))

    policy = snap["after"] if a.expect == "restricted" else snap["before"].get("value")
    expect_open = management_allowed(policy)
    status, detail = judge_management(http.mgmt_probe(mgmt, "ipv4"), expect_open)
    checks.append(check(f"management route {MANAGEMENT_PORT} via {mgmt}:443 untouched "
                        f"(expected {'open' if expect_open else 'denied'})", status, detail))
    return checks


def cmd_verify(a, clients, now, out):
    checks = verify(a, clients, now)
    result = "pass" if all(c["status"] == "pass" for c in checks) else "FAIL"
    emit(out, {"command": "verify", "expect": a.expect, "result": result, "checks": checks,
               "closed_means": list(CLOSED_SIGNALS),
               "closed_rule": "Closed is a POSITIVE refusal only: a connect error (refused), a reset, or no route. "
                              "Anything that completes TLS or HTTP is open or unknown, and open or unknown FAILS verify. "
                              "On the SNI-shared gateway the real denial may be a TLS/HTTP signature, in which case verify "
                              "fails until a drill observes what a closed gateway really does; it is never loosened silently.",
               "worker_origin_value": ORIGIN_ATTESTATION,
               "what_the_end_to_end_checks_can_show": END_TO_END_SHOWS if a.expect == "restricted" else None,
               "what_they_cannot_show": END_TO_END_CANNOT,
               "not_covered": ["independent external networks (single vantage)", "cached or literal-IP paths",
                               "existing long-lived connections", "provider read-back of /network and /compose_file",
                               "streaming/SSE behaviour"]})
    return 0 if result == "pass" else 1


# ---------------------------------------------------------------- undo

def cmd_undo(a, clients, now, out):
    snap = load_private_snapshot(a.snapshot)
    require(snap.get("app_id") == a.expect_app_id, "Snapshot belongs to a different app")
    # Validate every operator value that is printed back in the verify command.
    direct_hosts(a)
    check_tunnel_host(a.tunnel_host)
    private_file(a.receipt, "Receipt")
    require_new_path(a.patch_out, "Patch file")
    restore = run_switch(["--compose", a.compose, "--target", a.target, "--expect-app-id", a.expect_app_id,
                          "--restore", a.snapshot, "--apply" if a.apply else "--dry-run"])
    write_private(a.patch_out, restore["patch"])
    emit(out, {"command": "undo", "executed_by_this_script": "local restore " + ("staged" if a.apply else "dry-run only")
               + "; NO Phala call was made",
               "order": ["1. Compare the LIVE provider policy to the snapshot 'after'; on drift STOP and reconcile",
                         "2. Operator runs the PATCH below (HTTP first; keep tunnel and Worker unchanged)",
                         "3. Run the verify command; the Worker must not be pointed back at public -8000 before it passes"],
               "phala_command_for_authorized_operator": phala_command(restore["cvm_id"], a.patch_out),
               "payload": restore["patch"], "patch_file": str(Path(a.patch_out).resolve()),
               "snapshot_after_to_compare": snap["after"],
               "warning": "The PATCH restarts the CVM and interrupts both HTTP paths.",
               "then_verify": verify_command(a, "restored", a.receipt)})


# ---------------------------------------------------------------- CLI

def emit(out, value):
    out.write(json.dumps(value, indent=2) + "\n")


def parser():
    top = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = top.add_subparsers(dest="command", required=True)

    def add(name, help_, *groups):
        p = sub.add_parser(name, help=help_)
        p.add_argument("--expect-app-id", required=True)
        for group in groups:
            group(p)
        return p

    def cloudflare(p):
        p.add_argument("--tunnel-id", required=True)
        p.add_argument("--tunnel-host", required=True)
        p.add_argument("--account-id", required=True, help="32 hex characters")
        p.add_argument("--zone-id", required=True, help="32 hex characters")
        p.add_argument("--worker-script", default=DEFAULT_WORKER)
        p.add_argument("--expect-worker-version")
        p.add_argument("--attest-origin-is-tunnel-host", action="store_true",
                       help="operator attests the P3 set-origin step was given exactly https://<--tunnel-host>")

    def switch_inputs(p):
        p.add_argument("--compose", type=Path, required=True)
        p.add_argument("--target", type=Path, required=True)
        p.add_argument("--network", type=Path, required=True)
        p.add_argument("--snapshot", type=Path, required=True, help="NEW 0600 rollback snapshot path")

    def verify_inputs(p):
        p.add_argument("--instance-id", required=True)
        p.add_argument("--gateway-domain", required=True)
        p.add_argument("--tunnel-host", required=True)
        p.add_argument("--receipt", type=Path, required=True)

    add("preflight", "read-only evidence receipt", cloudflare).add_argument("--out", type=Path)
    add("plan", "preflight, then the switch plan and exact undo", cloudflare, switch_inputs)
    p = add("apply-patch", "stage locally and EMIT the Phala PATCH (never executes it)", cloudflare, switch_inputs)
    p.add_argument("--confirm", required=True)
    p.add_argument("--patch-out", type=Path, required=True)
    p.add_argument("--receipt-out", type=Path, required=True, help="NEW 0600 receipt file for verify")
    p = add("verify", "post-checks", verify_inputs)
    p.add_argument("--snapshot", type=Path, required=True)
    p.add_argument("--expect", choices=("restricted", "restored"), default="restricted")
    p.add_argument("--extra-host", action="append")
    p.add_argument("--allow-no-aaaa", action="store_true", help="accept a missing AAAA record as IPv6 evidence")
    p.add_argument("--max-receipt-age", type=int, default=3600)
    p = add("undo", "EMIT the reverse PATCH from the snapshot", verify_inputs)
    p.add_argument("--compose", type=Path, required=True)
    p.add_argument("--target", type=Path, required=True)
    p.add_argument("--snapshot", type=Path, required=True)
    p.add_argument("--patch-out", type=Path, required=True)
    p.add_argument("--apply", action="store_true", help="stage the local restore (default: dry-run)")
    return top


def real_clients(a, env):
    cf = None
    if a.command in ("preflight", "plan", "apply-patch"):
        token = env.get(CLOUDFLARE_TOKEN_ENV)
        require(token, f"Set {CLOUDFLARE_TOKEN_ENV} (a Cloudflare READ-only token) in the environment")
        cf = CloudflareReader(token, a.account_id, a.zone_id)
    return Clients(NetworkProbe(), cf)


def main(argv=None, clients=None, now=None, out=None, env=None):
    out = out or sys.stdout
    a = parser().parse_args(argv)
    now = now or utcnow()
    clients = clients or real_clients(a, os.environ if env is None else env)
    handler = {"preflight": cmd_preflight, "plan": cmd_plan, "apply-patch": cmd_apply_patch,
               "verify": cmd_verify, "undo": cmd_undo}[a.command]
    return handler(a, clients, now, out) or 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Refusal as error:
        print(f"Refused: {error}. No Phala or provider action was performed.", file=sys.stderr)
    except ClientError as error:
        print(f"Read failed: {error}. Nothing was changed.", file=sys.stderr)
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        # Parser/IO diagnostics can embed input content; report none of it.
        print("Refused: check inputs, files and permissions. No Phala or provider action was performed.",
              file=sys.stderr)
    sys.exit(1)
