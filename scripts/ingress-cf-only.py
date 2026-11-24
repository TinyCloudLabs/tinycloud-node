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
LABEL = ("operator evidence: automated reads of Cloudflare and node state plus ONE operator attestation (worker_origin), "
         "not a cryptographic attestation")
SNAPSHOT_NOTE = ("verified_origin.worker_origin is operator-attested via --attest-origin-is-tunnel-host, NOT verified "
                 "or read: the key name is the unmodified switch's, and its 'independent verification' gate is satisfied "
                 "by that attestation")
ORIGIN_ATTESTATION = ("operator-attested, NOT verified: the Worker's ORIGIN_URL is a secret whose value the Cloudflare "
                      "API never returns; it is recorded as the --tunnel-host the operator says the set-origin step received")
CONNECTOR_BASIS = "tunnel status healthy with active connections and none pending reconnect, as read from the Cloudflare API"
END_TO_END_SHOWS = ("node.tinycloud.xyz answers /info with the recorded node id while every probed gateway path shows an "
                    "accepted closed signature, so the Worker reaches the node by some route other than the closed gateway")
END_TO_END_CANNOT = ["that the secret equals the tunnel host (another independent origin serving the same node would "
                     "also pass)", "that no unprobed gateway host or address is used", "anything before the restriction: "
                     "while the gateway is open the secret may still point at it and node.* would also pass"]
# Accepted closed signatures. EMPTY on purpose: on an SNI-routed shared gateway a TCP refusal happens before SNI and can
# never be app-specific, and the real denial signature has never been observed. verify therefore cannot pass until a
# drill records the signature and it is added HERE, under review. There is no flag, environment variable or file that
# widens it; tests inject entries by patching this name.
ACCEPTED_CLOSED_SIGNALS = ()
NO_SIGNATURE_NOTICE = "no accepted closed signature yet: drill required"
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

    Every probe reports a distinct signal token, never a bare "closed": tcp_refused and tcp_reset (both ONLY at connect),
    reset_after_connect (a reset once connected: during TLS or HTTP), tls_rejected, closed_after_tls, http_<status>,
    http_200_unparsed, malformed_http, node_info, ssh_banner, non_ssh_data, timeout, no_route, no_aaaa, no_address,
    error. The caller decides which are acceptable; reset_after_connect is never eligible.
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
        """-> (addresses, failure). failure is 'no_aaaa' only for an IPv6 lookup that says NODATA/NONAME while the same
        name resolves over IPv4 (it exists, it has no AAAA); every other failure (NXDOMAIN, resolver error or
        timeout, an IPv4 miss) is 'no_address'."""
        try:
            return [i[4] for i in socket.getaddrinfo(host, port, self.FAMILIES[family], socket.SOCK_STREAM)], None
        except socket.gaierror as error:
            nodata = {socket.EAI_NONAME, getattr(socket, "EAI_NODATA", socket.EAI_NONAME)}
            if family == "ipv6" and error.errno in nodata:
                try:
                    if socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM):
                        return [], "no_aaaa"
                except socket.gaierror:
                    pass
            return [], "no_address"

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
                return "reset_after_connect", None
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
                    return "reset_after_connect", None
                except OSError:
                    return "error", None
        if response.status != 200:
            return f"http_{response.status}", None
        node_id = self._node_id(body)
        return ("node_info", node_id) if node_id else ("http_200_unparsed", None)

    def _run(self, host, family, port, banner):
        addresses, failure = self._addresses(host, port, family)
        if not addresses:
            return {"outcome": failure, "signals": [failure]}
        attempts = [self._attempt(address, host, banner) for address in addresses]
        signals = [signal for signal, _ in attempts]
        result = {"signals": signals, "outcome": signals[0] if len(set(signals)) == 1 else "mixed",
                  "addresses": [address[0] for address in addresses]}
        for signal, node_id in attempts:
            if signal == "node_info":
                return dict(result, outcome="node_info", node_id=node_id)
        return result

    def control(self, address, family, sni, port=443):
        """Positive control: a TLS/SNI connection to this exact address with a known-open SNI. -> signal token.
        A refusal counts as the gateway closing an app only if this completes (ssh_banner)."""
        return self._attempt((address, port), sni, True)[0]

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
    keys = ("app_id", "worker_origin", "tunnel_id", "worker_version_id", "worker_origin_binding", "tunnel_connections")
    return dict({k: receipt[k] for k in keys}, reads_observed_at_utc=receipt["verified_at_utc"],
                node_id_fingerprint=fingerprint(receipt["origin_node_id"]),
                connector_authenticated_basis=CONNECTOR_BASIS, worker_origin_value=ORIGIN_ATTESTATION,
                evidence_label=LABEL)


# ---------------------------------------------------------------- switch wrapper / plan

def run_switch(argv):
    result = subprocess.run([sys.executable, str(SWITCH), *map(str, argv)], text=True, capture_output=True)
    if result.returncode != 0:
        raise Refusal("The local ingress switch refused: " + (result.stderr.strip().splitlines() or ["no detail"])[0])
    return json.loads(result.stdout)


def annotate_snapshot(path):
    """The switch records worker_origin under verified_origin; here it is only operator-attested. Mark it in place
    (atomic replace, still 0600). The switch ignores the added keys on restore."""
    p = Path(path)
    snap = json.loads(p.read_text(encoding="utf-8"))
    evidence = snap.get("verified_origin")
    require(isinstance(evidence, dict), "Snapshot has no origin evidence to annotate")
    snap["verified_origin"] = dict(evidence, worker_origin_status=ORIGIN_ATTESTATION)
    snap["verified_origin_note"] = SNAPSHOT_NOTE
    tmp = p.with_name(p.name + ".annotating")
    write_private(tmp, snap)
    os.replace(tmp, p)


def stage(a, receipt, apply):
    with tempfile.TemporaryDirectory(prefix="ingress-cf-only-") as tmp:
        proof = Path(tmp) / "attested-origin.json"
        write_private(proof, receipt)
        staged = run_switch(["--compose", a.compose, "--target", a.target, "--expect-app-id", a.expect_app_id,
                             "--network", a.network, "--verified-origin", proof, "--snapshot", a.snapshot,
                             "--apply" if apply else "--dry-run"])
    if apply:
        annotate_snapshot(a.snapshot)
    return staged


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
               "verify_note": "Fill the quoted placeholders (instance id, gateway domain). verify cannot pass until a drill "
                              "records the real gateway denial signature and it is accepted in code: "
                              + NO_SIGNATURE_NOTICE + ". A correct restriction therefore reads as NOT PROVEN CLOSED today.",
               "after_verify": {"exit 0": "pass (unreachable until a drill signature is accepted)",
                                "exit 1": "OPEN (a path answers as the node, management answers although denied or is "
                                          "reached without a banner, or node.* is unhealthy): undo --snapshot "
                                          + str(Path(a.snapshot).resolve()),
                                "exit 3": "NOT PROVEN CLOSED (nothing seen open): do NOT undo and do NOT restart; hold "
                                          "and run the drill",
                                "exit 4": "REFUSED (stale receipt, bad input, failed read): nothing was changed or judged; "
                                          "fix the input and re-run; never undo on exit 4"}})


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
    for extra in getattr(a, "extra_host", None) or []:
        # An extra host must belong to the app or the instance, so a typo cannot name an unknown SNI.
        require(host_name(extra, "extra").endswith("." + gateway)
                and extra.startswith((a.expect_app_id + "-", a.instance_id + "-")),
                "--extra-host must be <app-id|instance-id>-<port>.<gateway-domain>")
        hosts.append(extra)
    return list(dict.fromkeys(hosts))


def management_host(a):
    """INFERENCE: management is the gateway route <app>-10022.<gateway>:443 (compose comment), not a host port."""
    return f"{a.expect_app_id}-{MANAGEMENT_PORT}.{host_name(a.gateway_domain, 'gateway')}"


def instance_management_host(a):
    """INFERENCE: the instance id has the same -10022 route as the app id."""
    return f"{a.instance_id}-{MANAGEMENT_PORT}.{host_name(a.gateway_domain, 'gateway')}"


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


def check(name, status, detail, kind=None, **evidence):
    """kind classifies a FAIL for verdict_of: 'open' (answered as the node), 'broken' (service or management unhealthy)
    or 'not_proven_closed' (default: not proven closed, nothing seen open)."""
    assert status in ("pass", "fail")
    item = dict({"check": name, "status": status, "ok": status == "pass", "detail": detail}, **evidence)
    if status == "fail":
        item["kind"] = kind or "not_proven_closed"
    return item


def signals_of(result):
    return list(result.get("signals") or [result.get("outcome") or "error"])


def judge_closed(result, family=None, allow_no_aaaa=False):
    """A path that must be closed passes only on an ACCEPTED closed signature (empty set today: nothing passes), or on
    the one waiver: DNS NODATA for AAAA (no_aaaa), IPv6 only, with the operator's explicit flag. A node answer, an
    open, unknown or unaccepted result (incl. tcp_refused, which cannot be app-specific on a shared SNI gateway) FAILs."""
    signals = signals_of(result)
    if "node_info" in signals:
        return "fail", "node answered /info: " + ",".join(signals)
    if all(s in ACCEPTED_CLOSED_SIGNALS or (s == "no_aaaa" and family == "ipv6" and allow_no_aaaa) for s in signals):
        note = ",".join(signals)
        return "pass", note + (" (waived by --allow-no-aaaa: DNS NODATA is not proof of no IPv6 path)"
                               if "no_aaaa" in signals else "")
    detail = ",".join(signals) + " is not an accepted closed signature"
    if not ACCEPTED_CLOSED_SIGNALS:
        detail += f": {NO_SIGNATURE_NOTICE}"
    if "tcp_refused" in signals:
        detail += " (a TCP refusal happens before SNI: on a shared gateway it is a local/on-path cause or an outage)"
    return "fail", detail


def judge_management(result, expect_open, family="ipv4", allow_no_aaaa=False):
    signals = signals_of(result)
    if expect_open:
        if all(s == "ssh_banner" for s in signals):
            return "pass", "SSH-2.0 banner read through the gateway route"
        if family == "ipv6" and allow_no_aaaa and all(s == "no_aaaa" for s in signals):
            return "pass", "no_aaaa (waived by --allow-no-aaaa: DNS NODATA is not proof of no IPv6 path)"
        return "fail", "no SSH banner: " + ",".join(signals)
    if "ssh_banner" in signals:
        return "fail", "management still answers although the policy denies it"
    return "fail", ",".join(signals) + (": a refusal of the management route cannot be corroborated, because no "
                                        "known-open SNI exists on the gateway when management is denied")


def answered_as_success(signals):
    """A restricted path that answers 2xx is open even when the body is not the node's (http_200_unparsed): S9. 404, TLS
    alerts and other non-2xx stay not_proven_closed."""
    return any(s == "node_info" or s == "http_200_unparsed"
               or (s.startswith("http_") and s[5:].isdigit() and 200 <= int(s[5:]) < 300) for s in signals)


# Signals that mean the gateway answered on the route but not with the SSH banner AFTER the connection was accepted. For a
# management route that must stay open this is a broken service (class open, exit 1). tcp_refused and tcp_reset are
# CONNECT-time and therefore pre-SNI: management is the same gateway IP:443, so they cannot be about this app (a
# gateway-wide outage, a local REJECT) and stay not_proven_closed (exit 3), like timeout, no_route, no_aaaa, no_address
# and error: a vantage limit must never read as "undo".
MANAGEMENT_REACHED_NO_BANNER = {"reset_after_connect", "tls_rejected", "closed_after_tls", "non_ssh_data", "malformed_http",
                                "http_200_unparsed"}


def management_kind(signals, expect_open):
    if not expect_open:
        return "open" if "ssh_banner" in signals else "not_proven_closed"
    reached = any(s in MANAGEMENT_REACHED_NO_BANNER or s.startswith("http_") for s in signals)
    return "broken" if reached else "not_proven_closed"


def verify(a, clients, now):
    snap = load_private_snapshot(a.snapshot)
    require(snap.get("app_id") == a.expect_app_id, "Snapshot belongs to a different app")
    receipt = json.loads(private_file(a.receipt, "Receipt").read_text(encoding="utf-8"))
    require(isinstance(receipt, dict) and receipt.get("app_id") == a.expect_app_id and receipt.get("origin_node_id")
            and receipt.get("origin_node_id") == receipt.get("public_node_id"), "Receipt is missing or inconsistent")
    require(receipt.get("tunnel_hostname") == a.tunnel_host
            and (snap.get("verified_origin") or {}).get("tunnel_id") == receipt.get("tunnel_id"),
            "Receipt, snapshot and --tunnel-host do not describe the same tunnel")
    require((snap.get("verified_origin") or {}).get("worker_origin_status") == ORIGIN_ATTESTATION,
            "Snapshot lacks the operator-attested origin annotation written by apply-patch")
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
                            f"status={info.get('status')} node_id_matches={info.get('node_id') == node}", kind="broken",
                            transport_failure=info.get("status") is None))

    waived = []
    mgmt_open = management_allowed(snap["after"]) if a.expect == "restricted" else None
    controls = {}

    def control(address, family):
        """Same-address positive control: TLS/SNI to this very IP with the REAL app's management host."""
        if address not in controls:
            controls[address] = http.control(address, family, mgmt)
        return controls[address]

    if a.expect == "restricted":
        # The instance id is operator input; bind it to evidence by requiring its own management route to answer.
        inst = instance_management_host(a)
        if mgmt_open:
            res = http.mgmt_probe(inst, "ipv4")
            ok = all(s == "ssh_banner" for s in signals_of(res))
            detail = "SSH-2.0 banner through the instance route" if ok else "no SSH banner: " + ",".join(signals_of(res))
        else:
            ok, detail = False, "no known-open SNI exists when the policy denies management"
        checks.append(check(f"--instance-id is a real gateway host (positive control {inst}:443) [INFERENCE: route]",
                            "pass" if ok else "fail", detail, kind="not_proven_closed"))
        for name in hosts:
            for family in ("ipv4", "ipv6"):
                result = http.probe(name, family, 443)
                status, detail = judge_closed(result, family, a.allow_no_aaaa)
                signals, addresses = signals_of(result), list(result.get("addresses") or [])
                evidence = {"addresses": addresses, "controls": {}}
                if status == "pass" and any(s in ACCEPTED_CLOSED_SIGNALS for s in signals):
                    if len(addresses) != len(signals):
                        status, detail = "fail", "no resolved address was recorded for the refusal: " + detail
                    elif not mgmt_open:
                        status, detail = "fail", ("a refusal cannot be corroborated: the policy denies management, so no "
                                                 "known-open SNI exists for a same-address control")
                    else:
                        for address, signal in zip(addresses, signals):
                            if signal not in ACCEPTED_CLOSED_SIGNALS:
                                continue
                            evidence["controls"][address] = control(address, family)
                            if evidence["controls"][address] != "ssh_banner":
                                status, detail = "fail", (f"positive control to {address} with SNI {mgmt} returned "
                                                          f"{evidence['controls'][address]}: the refusal is not shown to come "
                                                          "from the gateway closing this app (local/on-path reject, wrong "
                                                          "address or a gateway-wide outage)")
                                break
                if status == "pass" and "no_aaaa" in signals:
                    waived.append(name)
                checks.append(check(f"{name} fresh {family} connection shows an accepted closed signature "
                                    "(same-address positive control)", status, detail,
                                    kind="open" if answered_as_success(signals) else "not_proven_closed", **evidence))
    else:
        require(management_allowed(snap["before"].get("value")),
                "Previous policy was restrictive; restored expectations are not automated, verify by hand")
        result = http.probe(TEE_HOST, "ipv4", 443)
        good = result.get("outcome") == "node_info" and result.get("node_id") == node
        checks.append(check(f"{TEE_HOST} fresh ipv4 connection reaches the node again", "pass" if good else "fail",
                            ",".join(signals_of(result)), kind="broken"))

    policy = snap["after"] if a.expect == "restricted" else snap["before"].get("value")
    expect_open = management_allowed(policy)
    # Management is probed over IPv6 as well: an AAAA record that exists must answer; NODATA is the same waiver as above.
    for family in ("ipv4", "ipv6"):
        result = http.mgmt_probe(mgmt, family)
        status, detail = judge_management(result, expect_open, family, a.allow_no_aaaa)
        if status == "pass" and "no_aaaa" in signals_of(result):
            waived.append(mgmt)
        checks.append(check(f"management route {MANAGEMENT_PORT} via {mgmt}:443 over {family} untouched "
                            f"(expected {'open' if expect_open else 'denied'})", status, detail,
                            kind=management_kind(signals_of(result), expect_open),
                            addresses=list(result.get("addresses") or [])))
    return checks, waived


def record_verify(path, run, waiver):
    """Append this run (resolved addresses, controls) and any operator waiver to the receipt: atomic replace, 0600."""
    p = Path(path)
    receipt = json.loads(p.read_text(encoding="utf-8"))
    receipt["verify_runs"] = list(receipt.get("verify_runs") or []) + [run]
    if waiver:
        receipt["verify_waivers"] = list(receipt.get("verify_waivers") or []) + [waiver]
    tmp = p.with_name(p.name + ".record")
    write_private(tmp, receipt)
    os.replace(tmp, p)


def verdict_of(checks):
    """-> (class, exit code). 'open' (1): a probed path answered as the node, management answered although denied, expected-
    open management reached but gave no SSH banner, or node.*/tunnel/restored is unhealthy: undo territory.
    'not_proven_closed' (3): nothing was proven closed but nothing was seen open (and no verifier-side limit such as no
    route or a resolver failure): HOLD and run the drill; do NOT undo and do NOT restart. pass (0) is unreachable for
    restricted while the accepted signature set is empty."""
    failed = [c for c in checks if c["status"] != "pass"]
    if not failed:
        return "pass", 0
    if any(c.get("kind") in ("open", "broken") for c in failed):
        return "open", 1
    return "not_proven_closed", 3


EXIT_CODES = {
    "restricted": {"0": "pass", "1": "open: undo",
                   "3": "not_proven_closed: hold, check from a second network, run the drill, do not undo",
                   "4": "refused (no verdict, printed on stderr only): fix the input, never undo"},
    "restored": {"0": "pass", "1": "restored path broken: investigate from a second network, do NOT undo again",
                 "3": "restored not proven from this vantage: re-run from a second IPv6-capable network, do NOT undo again",
                 "4": "refused (no verdict, printed on stderr only): fix the input, never undo"},
}


def next_action(verdict, expect, checks):
    """Text per mode: after an undo (restored) 'undo' is never the advice. Decision table: exit AND verdict."""
    if verdict == "pass":
        return "none"
    failed = [c for c in checks if c["status"] != "pass"]
    if expect == "restored":
        if verdict == "open":
            return ("RESTORED PATH BROKEN (verdict open): the node path or management is not healthy after the restore. "
                    "Do NOT undo again: the restore is already applied. Investigate the tunnel, the Worker secret and the "
                    "connector, and confirm from a second network.")
        return ("RESTORED NOT PROVEN (verdict not_proven_closed) from this vantage, e.g. an IPv4-only vantage while "
                "management has an AAAA record: re-run from a second IPv6-capable network. Do NOT undo again. No drill is "
                "needed for restored.")
    if verdict == "open":
        text = ("OPEN (verdict open): a probed path answered as the node, or the service or management is unhealthy. Follow "
                "the runbook decision table: undo (restore) if the path is open or the service is down.")
        seen = [c for c in failed if c.get("kind") in ("open", "broken")]
        if seen and all(c.get("transport_failure") for c in seen):
            text += (" Every failing check is a transport failure of /info seen from this vantage only (no HTTP answer): "
                     "confirm from a second network before undo.")
        return text
    return ("NOT PROVEN CLOSED (verdict not_proven_closed), and nothing was seen open. Do NOT undo and do NOT restart on "
            "this result. From a SECOND, IPv6-capable network check that the -8000 hosts and tee.node.tinycloud.xyz /info "
            "do not return the node and that the management route (<app-id>-10022 on the gateway) still answers an "
            "SSH-2.0 banner, then run the drill. With the empty accepted-signature set a correct restriction also "
            "reads like this (see the runbook).")


def cmd_verify(a, clients, now, out):
    checks, waived = verify(a, clients, now)
    verdict, code = verdict_of(checks)
    result = "pass" if verdict == "pass" else "FAIL"
    waiver = ({"at_utc": now.isoformat(), "waiver": "allow-no-aaaa",
               "scope": "IPv6 probes whose DNS answer was NODATA for AAAA on a name that otherwise resolves; nothing else",
               "hosts_waived": list(dict.fromkeys(waived))} if a.allow_no_aaaa else None)
    try:
        record_verify(a.receipt, {"at_utc": now.isoformat(), "expect": a.expect, "result": result, "verdict": verdict,
                                  "accepted_closed_signals": list(ACCEPTED_CLOSED_SIGNALS),
                                  "checks": [{k: c[k] for k in ("check", "status", "kind", "addresses", "controls") if k in c}
                                             for c in checks]}, waiver)
        receipt_record = "resolved addresses and control results were appended to the receipt (verify_runs)"
    except Exception:
        # S10: a failed receipt write (leftover .record, disk full, permissions) must never turn a computed verdict, e.g.
        # open, into exit 4. The verdict is emitted with its own exit code and the failure is stated.
        receipt_record = ("FAILED: the receipt could not be updated; this run's addresses and controls were NOT recorded. "
                          "The verdict and exit code above are unaffected")
        print("Warning: " + receipt_record, file=sys.stderr)
    emit(out, {"command": "verify", "expect": a.expect, "result": result, "verdict": verdict, "exit_code": code,
               "exit_codes": EXIT_CODES[a.expect],
               "next_action": next_action(verdict, a.expect, checks), "checks": checks,
               "accepted_closed_signals": list(ACCEPTED_CLOSED_SIGNALS),
               "blocked": NO_SIGNATURE_NOTICE if a.expect == "restricted" and not ACCEPTED_CLOSED_SIGNALS else None,
               "closed_rule": "A path is closed only if it shows an ACCEPTED closed signature, and the accepted set is "
                              "empty until a drill records the real gateway denial and the signature is added in code "
                              "under review. A TCP refusal happens before SNI on a shared gateway, so it is never "
                              "app-specific; it means a local/on-path cause or an outage. Any signature added later also "
                              "needs a same-address positive control, and a reset counts only at connect. Open, unknown "
                              "and unaccepted results never pass; there is no flag to widen the set.",
               "receipt_record": receipt_record,
               "waivers": waiver or "none (--allow-no-aaaa not given)",
               "worker_origin_value": ORIGIN_ATTESTATION,
               "what_the_end_to_end_checks_can_show": END_TO_END_SHOWS if a.expect == "restricted" else None,
               "what_they_cannot_show": END_TO_END_CANNOT,
               "not_covered": ["independent external networks (single vantage)", "cached or literal-IP paths",
                               "existing long-lived connections", "provider read-back of /network and /compose_file",
                               "streaming/SSE behaviour"]})
    return code


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
               "snapshot_after_to_compare": snap["after"], "snapshot_origin_note": snap.get("verified_origin_note"),
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
    p.add_argument("--allow-no-aaaa", action="store_true",
                   help="waive ONLY an IPv6 probe whose DNS answer is NODATA for AAAA on a name that otherwise resolves; "
                        "an existing AAAA record is still probed; resolver errors/NXDOMAIN are not waived; "
                        "the waiver is recorded in the receipt")
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


EXIT_REFUSED = 4  # no verdict: bad operator input or a failed read. 1 is reserved for the open verdict (undo), 3 for hold


def main(argv=None, clients=None, now=None, out=None, env=None):
    """Returns the exit code. Refusals and failed reads return EXIT_REFUSED, never 1: nothing was changed or judged, and
    an operator or wrapper that undoes on exit 1 must never undo because of a stale receipt or a typo."""
    out = out or sys.stdout
    a = parser().parse_args(argv)
    try:
        now = now or utcnow()
        clients = clients or real_clients(a, os.environ if env is None else env)
        handler = {"preflight": cmd_preflight, "plan": cmd_plan, "apply-patch": cmd_apply_patch,
                   "verify": cmd_verify, "undo": cmd_undo}[a.command]
        return handler(a, clients, now, out) or 0
    except Refusal as error:
        print(f"Refused: {error}. No Phala or provider action was performed. Exit {EXIT_REFUSED}: nothing was changed or "
              "judged; fix the input; never undo on this exit.", file=sys.stderr)
    except ClientError as error:
        print(f"Read failed: {error}. Nothing was changed or judged. Exit {EXIT_REFUSED}; never undo on this exit.",
              file=sys.stderr)
    return EXIT_REFUSED


def cli(argv=None):
    """Process entry: exit code only. Any exception main() did not map (IO, parse, a bug) is exit 4: an uncaught traceback
    would exit 1, which means 'open: undo'. A failed receipt write is handled in cmd_verify and keeps the verdict's own
    code. argparse's SystemExit(2) passes through."""
    try:
        return main(argv)
    except Exception:
        # Parser/IO diagnostics can embed input content; report none of it.
        print("Error: an unexpected failure stopped the run. No verdict was computed: do NOT treat this as closed and do "
              f"NOT undo on this alone; rerun. Exit {EXIT_REFUSED}: nothing was changed. No Phala or provider action was "
              "performed.", file=sys.stderr)
        return EXIT_REFUSED


if __name__ == "__main__":
    sys.exit(cli())
