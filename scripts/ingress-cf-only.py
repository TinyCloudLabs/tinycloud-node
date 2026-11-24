#!/usr/bin/env python3
"""Cloudflare-only ingress wrapper: preflight, plan, apply-patch, verify, undo.

Wraps scripts/ingress-switch.py (run as a subprocess, unmodified). Network access is
read-only and sits behind injectable clients (Cloudflare GET reads, HTTPS/TCP probes).
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
from urllib.parse import urlsplit
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
CLOUDFLARE_TOKEN_ENV = "CLOUDFLARE_READ_TOKEN"
HEX40 = re.compile(r"[0-9a-f]{40}")
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


# ---------------------------------------------------------------- real read-only clients
# Never run against the network by this change; unit tests exercise them with fakes only.

class CloudflareReader:
    """GET-only Cloudflare API reads. The token never appears in any message."""
    API = "https://api.cloudflare.com/client/v4"

    def __init__(self, token, account_id, zone_id, opener=urlopen):
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
        deployments = self._get(f"/accounts/{self.account}/workers/scripts/{script}/deployments")
        versions = ((deployments or {}).get("deployments") or [{}])[0].get("versions") or []
        version = versions[0].get("version_id") if len(versions) == 1 and versions[0].get("percentage") == 100 else None
        settings = self._get(f"/accounts/{self.account}/workers/scripts/{script}/settings")
        # INFERENCE: the deployed variable is a plain_text binding named ORIGIN_URL (set with
        # `wrangler deploy --var`). Anything else (absent, duplicated, secret, other type) -> None.
        bindings = [b for b in (settings or {}).get("bindings") or [] if isinstance(b, dict) and b.get("name") == "ORIGIN_URL"]
        origin = bindings[0].get("text") if len(bindings) == 1 and bindings[0].get("type") == "plain_text" else None
        routes = self._get(f"/zones/{self.zone}/workers/routes") or []
        return {"version_id": version, "origin": origin if isinstance(origin, str) else None,
                "routes": [{"pattern": r.get("pattern"), "script": r.get("script")} for r in routes]}


class NetworkProbe:
    """HTTPS /info reads and fresh-connection probes from this host only (one vantage)."""
    FAMILIES = {"ipv4": socket.AF_INET, "ipv6": socket.AF_INET6}

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

    @staticmethod
    def _classify(error):
        if isinstance(error, (socket.timeout, TimeoutError)):
            return "timeout"
        if isinstance(error, (ssl.SSLError, EOFError, ConnectionRefusedError, ConnectionResetError,
                              ConnectionAbortedError, BrokenPipeError)):
            return "refused"
        return "refused" if getattr(error, "errno", None) in (errno.ECONNREFUSED, errno.ECONNRESET) else "error"

    def probe(self, host, family, port=443):
        """-> {'outcome': node_info|refused|no_address|timeout|error, 'node_id'?}"""
        addresses = self._addresses(host, port, family)
        if not addresses:
            return {"outcome": "no_address"}
        worst = "refused"
        for address in addresses:
            try:
                context = ssl.create_default_context()
                context.check_hostname, context.verify_mode = False, ssl.CERT_NONE  # reachability only
                with socket.create_connection(address[:2], timeout=8) as raw:
                    with context.wrap_socket(raw, server_hostname=host) as stream:
                        stream.sendall(f"GET /info HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
                        data = b""
                        while len(data) < 65536:
                            chunk = stream.recv(8192)
                            if not chunk:
                                break
                            data += chunk
            except (OSError, EOFError) as error:
                outcome = self._classify(error)
                worst = outcome if outcome != "refused" else worst
                continue
            head, _, body = data.partition(b"\r\n\r\n")
            node_id = self._node_id(body) if head.startswith((b"HTTP/1.1 200", b"HTTP/1.0 200")) else None
            if node_id:
                return {"outcome": "node_info", "node_id": node_id}
        return {"outcome": worst}

    def tcp_probe(self, host, port, family):
        """-> open|refused|no_address|timeout|error"""
        addresses = self._addresses(host, port, family)
        if not addresses:
            return "no_address"
        worst = "refused"
        for address in addresses:
            try:
                socket.create_connection(address[:2], timeout=8).close()
                return "open"
            except OSError as error:
                outcome = self._classify(error)
                worst = outcome if outcome != "refused" else worst
        return worst


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
    host = cfg["tunnel_host"]
    check_tunnel_host(host)
    http, cf = clients.http, clients.cf

    tunnel = cf.tunnel(cfg["tunnel_id"])
    require(isinstance(tunnel, dict) and tunnel.get("id") == cfg["tunnel_id"] and not tunnel.get("deleted_at"),
            "Cloudflare tunnel read does not match the expected tunnel")
    connections = tunnel.get("connections")
    require(tunnel.get("status") == "healthy" and isinstance(connections, list) and connections
            and all(isinstance(c, dict) and not c.get("is_pending_reconnect") for c in connections),
            "Tunnel connector is not healthy with authenticated active connections")

    ingress = cf.tunnel_ingress(cfg["tunnel_id"])
    require(isinstance(ingress, list) and any(
        isinstance(r, dict) and r.get("hostname") == host and r.get("service") == TUNNEL_SERVICE for r in ingress),
        "Tunnel ingress does not route the tunnel hostname to the node service")

    records = cf.dns_records(host)
    require(isinstance(records, list) and len(records) == 1 and isinstance(records[0], dict)
            and records[0].get("type") == "CNAME" and records[0].get("proxied") is True
            and records[0].get("content") == f"{cfg['tunnel_id']}.cfargotunnel.com",
            "Tunnel hostname is not bound to the expected tunnel")

    worker = cf.worker(cfg["worker_script"])
    require(isinstance(worker, dict) and isinstance(worker.get("version_id"), str) and worker["version_id"],
            "Worker version could not be read")
    require(isinstance(worker.get("origin"), str) and not (urlsplit(worker["origin"]).hostname or "").endswith(".phala.network"),
            "Deployed Worker ORIGIN_URL is missing or is a Phala gateway host; not Cloudflare-only")
    require(worker.get("origin") == f"https://{host}", "Worker origin is not the tunnel hostname")
    if cfg.get("expect_worker_version"):
        require(worker["version_id"] == cfg["expect_worker_version"], "Worker version differs from the expected version")
    routes = {r.get("pattern"): r.get("script") for r in worker.get("routes") or [] if isinstance(r, dict)}
    require(routes.get(f"{PUBLIC_HOST}/*") == cfg["worker_script"], "node.tinycloud.xyz is not routed to the Worker")

    origin, public = http.info(host), http.info(PUBLIC_HOST)
    require(origin.get("status") == 200 and public.get("status") == 200, "/info is not healthy on both routes")
    require(origin.get("node_id") and origin.get("node_id") == public.get("node_id"),
            "Node ids differ or are missing between the tunnel host and node.tinycloud.xyz")
    return {"app_id": cfg["app_id"], "public_url": f"https://{PUBLIC_HOST}", "worker_origin": f"https://{host}",
            "tunnel_hostname": host, "tunnel_id": cfg["tunnel_id"], "verified_at_utc": now.isoformat(),
            "connector_authenticated": True, "origin_status": 200, "public_status": 200,
            "origin_node_id": origin["node_id"], "public_node_id": public["node_id"],
            "worker_version_id": worker["version_id"], "tunnel_connections": len(connections),
            "evidence_label": LABEL}


def summarize(receipt):
    """Receipt fields safe to print: node ids appear only as short fingerprints."""
    keys = ("app_id", "worker_origin", "tunnel_id", "worker_version_id", "tunnel_connections", "verified_at_utc")
    return dict({k: receipt[k] for k in keys}, node_id_fingerprint=fingerprint(receipt["origin_node_id"]),
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


def verify_command(a, expect, receipt_path="RECEIPT.json"):
    parts = ["python3", "scripts/ingress-cf-only.py", "verify", "--expect", expect,
             "--expect-app-id", a.expect_app_id, "--snapshot", str(a.snapshot),
             "--receipt", receipt_path, "--tunnel-host", a.tunnel_host or "TUNNEL_HOST"]
    for flag, value in (("--instance-id", a.instance_id), ("--gateway-domain", a.gateway_domain),
                        ("--management-endpoint", a.management_endpoint)):
        parts += [flag, value or f"<{flag[2:].upper()}>"]
    return " ".join(shlex.quote(p) if not p.startswith("<") else p for p in parts)


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
    receipt, sw, digest = build_plan(a, clients, now)
    require(hmac.compare_digest(a.confirm, digest), "Confirm does not match a fresh plan; rerun plan and review it")
    require(not Path(a.patch_out).exists() and not Path(a.snapshot).exists(), "Patch file and snapshot must be new paths")
    staged = stage(a, receipt, apply=True)
    require(staged["patch"] == sw["patch"], "Staged patch differs from the confirmed plan")
    write_private(a.patch_out, staged["patch"])
    emit(out, {"command": "apply-patch", "executed_by_this_script": "local staging only; NO Phala call was made",
               "phala_command_for_authorized_operator": phala_command(sw["cvm_id"], a.patch_out),
               "payload": staged["patch"], "patch_file": str(Path(a.patch_out).resolve()),
               "snapshot": str(Path(a.snapshot).resolve()), "evidence": summarize(receipt),
               "warning": "Under a GO only. The PATCH restarts the CVM and interrupts both HTTP paths.",
               "then_verify": verify_command(a, "restricted", "RECEIPT.json"),
               "if_bad": "undo --snapshot " + str(Path(a.snapshot).resolve())})


def cmd_preflight(a, clients, now, out):
    receipt = preflight(cfg_of(a), clients, now)
    if a.out:
        write_private(a.out, receipt)
    emit(out, {"command": "preflight", "result": "pass", "receipt_file": str(Path(a.out).resolve()) if a.out else None,
               "evidence": summarize(receipt)})


def cfg_of(a):
    return {"app_id": a.expect_app_id, "tunnel_id": a.tunnel_id, "tunnel_host": a.tunnel_host,
            "worker_script": a.worker_script, "expect_worker_version": a.expect_worker_version}


# ---------------------------------------------------------------- verify

def direct_hosts(a):
    require(HEX40.fullmatch(a.expect_app_id), "Expected a 40-hex app ID")
    require(a.instance_id and LABEL_RE.fullmatch(a.instance_id), "--instance-id is required")
    gateway = host_name(a.gateway_domain, "gateway")
    hosts = [TEE_HOST]
    for ident in (a.expect_app_id, a.instance_id):
        hosts += [f"{ident}-{suffix}.{gateway}" for suffix in GATEWAY_SUFFIXES]
    hosts += [host_name(h, "extra") for h in a.extra_host or []]
    return list(dict.fromkeys(hosts))


def management_allowed(policy):
    """INFERENCE: no policy, or restrict_mode false, leaves management reachable."""
    if not isinstance(policy, dict) or policy.get("restrict_mode") is not True:
        return True
    return any(isinstance(p, dict) and p.get("port") == MANAGEMENT_PORT for p in policy.get("ports", []))


def load_private_snapshot(path):
    p = Path(path)
    require(p.is_file() and not p.is_symlink(), "Snapshot must be an existing regular file")
    st = p.stat()
    require(st.st_mode & 0o077 == 0 and st.st_uid == os.getuid(), "Snapshot must be owner-only (0600)")
    snap = json.loads(p.read_text(encoding="utf-8"))
    require(isinstance(snap, dict) and isinstance(snap.get("before"), dict) and "after" in snap,
            "Snapshot is not a recorded ingress policy")
    return snap


def check(name, ok, detail):
    return {"check": name, "ok": bool(ok), "detail": detail}


def verify(a, clients, now):
    snap = load_private_snapshot(a.snapshot)
    require(snap.get("app_id") == a.expect_app_id, "Snapshot belongs to a different app")
    receipt = json.loads(Path(a.receipt).read_text(encoding="utf-8"))
    require(isinstance(receipt, dict) and receipt.get("app_id") == a.expect_app_id and receipt.get("origin_node_id")
            and receipt.get("origin_node_id") == receipt.get("public_node_id"), "Receipt is missing or inconsistent")
    age = (now - datetime.fromisoformat(receipt["verified_at_utc"].replace("Z", "+00:00"))).total_seconds()
    require(0 <= age <= a.max_receipt_age, "Receipt is stale; rerun preflight")
    check_tunnel_host(a.tunnel_host)
    host, port = (a.management_endpoint or "").rpartition(":")[::2]
    require(host and port == str(MANAGEMENT_PORT), "--management-endpoint HOST:10022 is required")
    host_name(host, "management")
    hosts = direct_hosts(a)
    http = clients.http
    node = receipt["origin_node_id"]
    checks = []

    for label, name in (("tunnel host", a.tunnel_host), ("node.tinycloud.xyz", PUBLIC_HOST)):
        info = http.info(name)
        checks.append(check(f"{label} /info healthy with the recorded node id",
                            info.get("status") == 200 and info.get("node_id") == node,
                            f"status={info.get('status')} node_id_matches={info.get('node_id') == node}"))

    if a.expect == "restricted":
        for name in hosts:
            for family in ("ipv4", "ipv6"):
                result = http.probe(name, family, 443)
                outcome = result.get("outcome")
                ok = outcome == "refused" or (outcome == "no_address" and family == "ipv6" and a.allow_no_aaaa)
                note = outcome + (" (explicitly accepted: no AAAA is not proof of no IPv6 path)" if ok and outcome == "no_address" else "")
                checks.append(check(f"{name} fresh {family} connection refused", ok, note))
    else:
        require(management_allowed(snap["before"].get("value")),
                "Previous policy was restrictive; restored expectations are not automated, verify by hand")
        result = http.probe(TEE_HOST, "ipv4", 443)
        checks.append(check(f"{TEE_HOST} fresh ipv4 connection reaches the node again",
                            result.get("outcome") == "node_info" and result.get("node_id") == node,
                            result.get("outcome", "?")))

    policy = snap["after"] if a.expect == "restricted" else snap["before"].get("value")
    expected = "open" if management_allowed(policy) else "refused"
    seen = http.tcp_probe(host, MANAGEMENT_PORT, "ipv4")
    checks.append(check(f"management port {MANAGEMENT_PORT} untouched (expected {expected})", seen == expected, seen))
    return checks


def cmd_verify(a, clients, now, out):
    checks = verify(a, clients, now)
    passed = all(c["ok"] for c in checks)
    emit(out, {"command": "verify", "expect": a.expect, "result": "pass" if passed else "FAIL", "checks": checks,
               "not_covered": ["independent external networks (single vantage)", "cached or literal-IP paths",
                               "existing long-lived connections", "provider read-back of /network and /compose_file",
                               "streaming/SSE behaviour"]})
    return 0 if passed else 1


# ---------------------------------------------------------------- undo

def cmd_undo(a, clients, now, out):
    snap = load_private_snapshot(a.snapshot)
    require(snap.get("app_id") == a.expect_app_id, "Snapshot belongs to a different app")
    require(not Path(a.patch_out).exists(), "Patch file must be a new path")
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
               "then_verify": verify_command(a, "restored")})


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
        p.add_argument("--account-id", required=True)
        p.add_argument("--zone-id", required=True)
        p.add_argument("--worker-script", default=DEFAULT_WORKER)
        p.add_argument("--expect-worker-version")

    def switch_inputs(p):
        p.add_argument("--compose", type=Path, required=True)
        p.add_argument("--target", type=Path, required=True)
        p.add_argument("--network", type=Path, required=True)
        p.add_argument("--snapshot", type=Path, required=True, help="NEW 0600 rollback snapshot path")

    def verify_inputs(p):
        p.add_argument("--instance-id", required=True)
        p.add_argument("--gateway-domain", required=True)
        p.add_argument("--management-endpoint", required=True, help="HOST:10022")
        p.add_argument("--tunnel-host", required=True)
        p.add_argument("--receipt", type=Path, required=True)

    add("preflight", "read-only evidence receipt", cloudflare).add_argument("--out", type=Path)
    add("plan", "preflight, then the switch plan and exact undo", cloudflare, switch_inputs)
    p = add("apply-patch", "stage locally and EMIT the Phala PATCH (never executes it)", cloudflare, switch_inputs)
    p.add_argument("--confirm", required=True)
    p.add_argument("--patch-out", type=Path, required=True)
    for p in (sub.choices["apply-patch"], sub.choices["plan"]):
        p.set_defaults(instance_id=None, gateway_domain=None, management_endpoint=None)
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
