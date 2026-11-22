#!/usr/bin/env python3
"""Stage a Phala HTTP ingress policy locally. Never contacts a provider or deploys."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from urllib.parse import urlsplit
from uuid import UUID


CLOSED_PORTS = {443, 8000}
# The SSH management relay's port. Since TC-3838 the compose publishes nothing
# there; the switch keeps its prior policy entry so it neither widens nor
# narrows anything beyond the node HTTP ports.
MANAGEMENT_PORT = 10022


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load(path):
    with open(path, encoding="utf-8") as stream:
        value = json.load(stream)
    require(isinstance(value, dict), "Expected a JSON object")
    return value


def https_host(value):
    url = urlsplit(value)
    require(url.scheme == "https" and url.hostname and url.port in (None, 443)
            and not url.username and not url.password and url.path in ("", "/")
            and not url.query and not url.fragment, "Expected an HTTPS origin hostname")
    return url.hostname


def verified_origin(path, app_id):
    require(path is not None, "Supply --verified-origin from separately authorized operator verification")
    receipt = load(path)
    require(receipt.get("app_id") == app_id, "Origin evidence belongs to a different app")
    require(receipt.get("public_url") == "https://node.tinycloud.xyz", "Unexpected public HTTP route")
    host = https_host(receipt["worker_origin"])
    require(host == receipt.get("tunnel_hostname") and host not in {
        "node.tinycloud.xyz", "tee.node.tinycloud.xyz"}
        and not host.endswith((".phala.network", ".cfargotunnel.com")),
        "Worker origin must be the independently verified tunnel hostname, not the public gateway")
    UUID(receipt["tunnel_id"])
    observed = datetime.fromisoformat(receipt["verified_at_utc"].replace("Z", "+00:00"))
    require(observed.utcoffset() == timezone.utc.utcoffset(observed)
            and observed <= datetime.now(timezone.utc), "Invalid origin verification UTC timestamp")
    require(receipt.get("connector_authenticated") is True, "Tunnel authentication was not verified")
    require(receipt.get("origin_status") == 200 and receipt.get("public_status") == 200
            and receipt.get("origin_node_id")
            and receipt.get("origin_node_id") == receipt.get("public_node_id"),
            "Independent origin and public route must have verified matching healthy node identities")
    return {key: receipt[key] for key in ("worker_origin", "tunnel_id", "verified_at_utc")}


def restricted_policy(compose, network, cvm_id):
    require(network.get("cvm_id") == cvm_id, "Network inventory belongs to a different CVM")
    require(network.get("is_online") is True and network.get("error") is None,
            "Gateway state is unknown; obtain complete operator network evidence")
    require(network.get("port_mappings") == [],
            "Direct host mappings require a separate reviewed control; refusing gateway-only isolation")
    ingress = network.get("ingress")
    require(isinstance(ingress, dict) and ingress.get("gateway_enabled") is True
            and compose.get("gateway_enabled") is True, "Expected enabled gateway ingress")
    old = compose.get("port_policy")
    require(ingress.get("port_policy") == old, "Local policy and network inventory differ")
    management = {"port": MANAGEMENT_PORT, "pp": False}
    if old is not None:
        require(isinstance(old, dict) and isinstance(old.get("restrict_mode"), bool)
                and isinstance(old.get("ports"), list), "Unknown gateway policy shape")
        require(all(isinstance(p, dict) and type(p.get("port")) is int
                    and p["port"] in CLOSED_PORTS | {MANAGEMENT_PORT} for p in old["ports"]),
                "Additional gateway ports need explicit review; refusing to change unrelated ingress")
        ports = {p["port"]: p for p in old["ports"]}
        require(len(ports) == len(old["ports"]), "Duplicate gateway port policy")
        management = ports.get(MANAGEMENT_PORT, management if not old["restrict_mode"] else None)
    return {"restrict_mode": True, "ports": [management] if management else []}


def replace_local(path, original, updated, mode):
    # Preserve unrelated fields and refuse a file changed after the plan was computed.
    require(path.read_bytes() == original, "Local compose changed; regenerate the plan")
    fd, name = tempfile.mkstemp(prefix=".ingress-switch-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), mode)
            json.dump(updated, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        require(path.read_bytes() == original, "Local compose changed; regenerate the plan")
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def main():
    parser = argparse.ArgumentParser(description=__doc__, epilog=(
        "Default: dry-run, no writes. --apply changes ONLY the local JSON file. "
        "Provider execution, tunnel setup, routing verification and DNS are separate operator actions. "
        "See docs/runbooks/http-ingress-switch.md."))
    parser.add_argument("--compose", type=Path, required=True, help="Local Phala app-compose JSON, not Docker YAML")
    parser.add_argument("--target", type=Path, required=True, help="Captured CVM metadata JSON with id and app_id")
    parser.add_argument("--expect-app-id", required=True, help="Explicit expected 40-hex Phala app ID")
    parser.add_argument("--network", type=Path, help="Captured /network JSON plus cvm_id")
    parser.add_argument("--verified-origin", type=Path, help="Operator receipt of authenticated independent tunnel + Worker routing")
    parser.add_argument("--snapshot", type=Path, help="New private rollback file; required with --apply when restricting")
    parser.add_argument("--restore", type=Path, help="Restore the exact recorded policy, without requiring a healthy tunnel")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true", help="Write local config only; NEVER execute a production change")
    mode.add_argument("--dry-run", action="store_true", help="Explicit no-write preview (also the default)")
    args = parser.parse_args()
    require(re.fullmatch(r"[0-9a-f]{40}", args.expect_app_id), "Expected a 40-hex app ID")
    require(not args.compose.is_symlink() and args.compose.is_file(), "Compose must be an existing regular local file")
    path = args.compose.resolve()
    original = path.read_bytes()
    compose = json.loads(original)
    require(isinstance(compose, dict), "Expected an app-compose JSON object")
    target = load(args.target)
    require(target.get("app_id") == args.expect_app_id and re.fullmatch(r"cvm_[A-Za-z0-9]+", target.get("id", "")),
            "Explicit app ID and captured CVM target must match")
    before = {"present": "port_policy" in compose, "value": compose.get("port_policy")}
    evidence = None
    if args.restore:
        saved = load(args.restore)
        require(saved.get("compose_path") == str(path) and saved.get("app_id") == args.expect_app_id
                and saved.get("cvm_id") == target["id"], "Rollback snapshot target does not match")
        require(compose.get("port_policy") == saved["after"], "Policy drift; refusing to overwrite another change")
        after = saved["before"]
    else:
        require(args.network is not None, "Supply --network inventory")
        evidence = verified_origin(args.verified_origin, args.expect_app_id)
        after = {"present": True, "value": restricted_policy(compose, load(args.network), target["id"])}
        require(before != after, "Policy is already restricted; keep the original rollback snapshot")
    if args.apply:
        if not args.restore:
            require(args.snapshot is not None, "--apply requires a new --snapshot")
            require(args.snapshot.resolve() not in {path, args.target.resolve(), args.network.resolve(),
                                                   args.verified_origin.resolve()}, "Snapshot must be a separate new file")
            saved = {"app_id": args.expect_app_id, "cvm_id": target["id"], "compose_path": str(path),
                     "created_at_utc": datetime.now(timezone.utc).isoformat(), "before": before,
                     "after": after["value"], "verified_origin": evidence}
            # Exclusive creation: never replace the only record of previous values.
            with open(args.snapshot, "x", encoding="utf-8", opener=lambda p, f: os.open(p, f, 0o600)) as stream:
                json.dump(saved, stream, indent=2)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
        if after["present"]:
            compose["port_policy"] = after["value"]
        else:
            compose.pop("port_policy", None)
        replace_local(path, original, compose, stat.S_IMODE(path.stat().st_mode))
    # Only policy values are printed, never compose contents, headers or credentials.
    print(json.dumps({"applied_local": args.apply, "cvm_id": target["id"], "before": before,
                      "after": after, "patch": {"compose": {"port_policy": after["value"]}}}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        # Parser/IO diagnostics can embed input content; report no raw exception or provider body.
        print("Ingress switch refused: check target, complete network inventory, verified independent origin, "
              "snapshot, file permissions and policy drift. No provider action was performed.", file=sys.stderr)
        sys.exit(1)
