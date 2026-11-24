#!/usr/bin/env python3
"""Instant, no-restart Cloudflare-side ingress lever: plan / apply / undo / verify (TC-4194).

Acts only on traffic that reaches Cloudflare for a PROXIED hostname. It does not close the
Phala origin hostnames and does not stop L3/L4 floods at the host. Dry-run is the default:
`plan` is read-only; `apply` and `undo` change nothing without `--confirm <plan-hash>`.
See docs/runbooks/cf-instant-switch.md.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

API = "https://api.cloudflare.com/client/v4"
PROG = "scripts/ingress-cf-switch.py"
MARKER = "TC-4194 instant ingress switch (scripts/ingress-cf-switch.py)"
WAF_PHASE = "http_request_firewall_custom"
WAF_ACTIONS = ("block", "managed_challenge", "js_challenge", "challenge")
SNAPSHOT_FORMAT = 1
VOLATILE_RULE_KEYS = {"id", "version", "last_updated", "ref"}
HOST_RE = re.compile(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+")
LIMITS = [
    "Acts only on requests reaching Cloudflare for a PROXIED hostname; a DNS-only hostname is unaffected.",
    "Does not close the Phala origin hostnames and does not stop L3/L4 floods at the host.",
]


class Refused(Exception):
    """Precondition or safety refusal: nothing was changed."""


class CfError(Exception):
    """Cloudflare API failure. Message never contains headers, bodies or the token."""

    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


def require(condition, message):
    if not condition:
        raise Refused(message)


def tail(value):
    return "…" + str(value)[-4:]


def canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def digest(value):
    return hashlib.sha256(canon(value).encode()).hexdigest()


def now():
    return datetime.now(timezone.utc).isoformat()


class CloudflareClient:
    """Real client. Not exercised against the network anywhere in this repository."""

    def __init__(self, token, opener=urlopen, timeout=20):
        self._token = token
        self._opener = opener
        self._timeout = timeout

    def _call(self, op, method, path, body=None):
        data = None if body is None else json.dumps(body).encode()
        request = Request(API + path, data=data, method=method)
        request.add_header("Authorization", "Bearer " + self._token)
        request.add_header("Content-Type", "application/json")
        try:
            with self._opener(request, timeout=self._timeout) as response:
                payload = json.load(response)
        except HTTPError as error:
            raise CfError(f"{op}: HTTP {error.code}", status=error.code) from None
        except (URLError, OSError, ValueError) as error:
            raise CfError(f"{op}: {type(error).__name__}") from None
        if not isinstance(payload, dict) or not payload.get("success"):
            codes = [e.get("code") for e in (payload.get("errors") or []) if isinstance(e, dict)] \
                if isinstance(payload, dict) else []
            raise CfError(f"{op}: Cloudflare reported failure, codes {codes}")
        return payload.get("result")

    def security_level(self, zone):
        return self._call("security_level", "GET", f"/zones/{zone}/settings/security_level")["value"]

    def set_security_level(self, zone, value):
        self._call("set_security_level", "PATCH", f"/zones/{zone}/settings/security_level", {"value": value})

    def entrypoint_rules(self, zone):
        try:
            result = self._call("entrypoint_rules", "GET", f"/zones/{zone}/rulesets/phases/{WAF_PHASE}/entrypoint")
        except CfError as error:
            if error.status == 404:
                return None
            raise
        return result.get("rules") or []

    def put_entrypoint_rules(self, zone, rules):
        self._call("put_entrypoint_rules", "PUT", f"/zones/{zone}/rulesets/phases/{WAF_PHASE}/entrypoint",
                   {"rules": rules})

    def worker_routes(self, zone):
        return self._call("worker_routes", "GET", f"/zones/{zone}/workers/routes")

    def set_route_script(self, zone, route_id, pattern, script):
        self._call("set_route_script", "PUT", f"/zones/{zone}/workers/routes/{route_id}",
                   {"pattern": pattern, "script": script})

    def dns_records(self, zone, name):
        return self._call("dns_records", "GET", f"/zones/{zone}/dns_records?per_page=100&name={quote(name)}")

    def update_dns_record(self, zone, record_id, body):
        self._call("update_dns_record", "PATCH", f"/zones/{zone}/dns_records/{record_id}", body)

    def create_dns_record(self, zone, body):
        self._call("create_dns_record", "POST", f"/zones/{zone}/dns_records", body)

    def delete_dns_record(self, zone, record_id):
        self._call("delete_dns_record", "DELETE", f"/zones/{zone}/dns_records/{record_id}")


# ---- levers: read / desired / is_applied / same / rest_equal / write / describe ----

def norm_rule(rule):
    return {k: v for k, v in rule.items() if k not in VOLATILE_RULE_KEYS}


class LeverBase:
    needs_proxied = True  # lever is inert unless the host is proxied through Cloudflare
    zone_wide = False

    def gates(self, before):
        """(flag attribute, message) pairs: refused at apply unless the matching --flag is given."""
        return []

    def warnings(self, before):
        return []

    def verify_note(self, snapshot):
        return None

    def read_lenient(self):
        return self.read()


class WafLever(LeverBase):
    name = "waf"

    def __init__(self, client, zone, host, params):
        self.client, self.zone, self.host, self.params = client, zone, host, params

    def rule(self):
        return {"action": self.params["action"], "expression": f'(http.host eq "{self.host}")',
                "description": MARKER, "enabled": True}

    def read(self):
        rules = self.client.entrypoint_rules(self.zone)
        return {"exists": rules is not None, "rules": list(rules or [])}

    @staticmethod
    def _ours(rules):
        return [r for r in rules if r.get("description") == MARKER]

    @staticmethod
    def _others(state):
        return [norm_rule(r) for r in state["rules"] if r.get("description") != MARKER]

    def is_applied(self, state):
        ours = self._ours(state["rules"])
        return len(ours) == 1 and all(ours[0].get(k) == v for k, v in self.rule().items())

    def desired(self, state):
        if self._ours(state["rules"]):
            require(self.is_applied(state), "A rule carrying this tool's marker exists with different settings "
                    "(or is duplicated); inspect it and undo with the snapshot that created it")
            return state
        return {"exists": True, "rules": [self.rule()] + state["rules"]}

    def same(self, a, b):
        return [norm_rule(r) for r in a["rules"]] == [norm_rule(r) for r in b["rules"]]

    def rest_equal(self, current, before):
        return self._others(current) == self._others(before)

    def write(self, state):
        self.client.put_entrypoint_rules(self.zone, state["rules"])

    def describe(self, before, after):
        others = self._others(before)
        return ({"call": f"PUT zones/{tail(self.zone)}/rulesets/phases/{WAF_PHASE}/entrypoint",
                 "insert_rule_at_position": 1, "rule": self.rule(),
                 "existing_rules": {"count": len(others), "sha256": digest(others)},
                 "entrypoint_existed": before["exists"]},
                {"call": f"PUT zones/{tail(self.zone)}/rulesets/phases/{WAF_PHASE}/entrypoint",
                 "restore": "the exact rule list recorded in the snapshot (ids and order preserved)",
                 "restored_rules": {"count": len(before["rules"]), "sha256": digest(before["rules"])},
                 "note": "an entrypoint that did not exist is restored as an empty rule list"})

    def extra_guard(self, current, snapshot):
        expression = self._ours(current["rules"])[0]["expression"] if self.is_applied(current) else ""
        # Quoted: "node.example" is a substring of "tee.node.example", but not of its quoted form.
        return {"our_rule_does_not_match_protected_host": f'"{snapshot["protect_host"]}"' not in expression}


class SecurityLevelLever(LeverBase):
    name = "security-level"
    zone_wide = True

    def __init__(self, client, zone, host, params):
        self.client, self.zone, self.host = client, zone, host

    def gates(self, before):
        return [("allow_zone_wide", "ZONE-WIDE: every proxied hostname in the zone, including the protected "
                 "host, is challenged; API clients fail the challenge")]

    def verify_note(self, snapshot):
        return (f"zone-wide lever: {snapshot['protect_host']} is challenged by design; "
                "its routes/DNS being unchanged does not mean it is unaffected")

    def read(self):
        return {"value": self.client.security_level(self.zone)}

    def is_applied(self, state):
        return state["value"] == "under_attack"

    def desired(self, state):
        return {"value": "under_attack"}

    def same(self, a, b):
        return a == b

    def rest_equal(self, current, before):
        return True

    def write(self, state):
        self.client.set_security_level(self.zone, state["value"])

    def describe(self, before, after):
        call = f"PATCH zones/{tail(self.zone)}/settings/security_level"
        return ({"call": call, "from": before["value"], "to": after["value"]},
                {"call": call, "to": before["value"]})

    def extra_guard(self, current, snapshot):
        return {}


class RouteLever(LeverBase):
    name = "worker-route"

    def __init__(self, client, zone, host, params):
        self.client, self.zone, self.host = client, zone, host

    def gates(self, before):
        return [("allow_no_block", "DOES NOT BLOCK: proxied requests pass straight to the DNS origin "
                 "(more exposure, not less)")]

    def read(self):
        pattern = f"{self.host}/*"
        found = [r for r in self.client.worker_routes(self.zone) if r.get("pattern") == pattern]
        require(len(found) == 1, f"Expected exactly one Worker route with pattern {pattern}")
        return {"id": found[0]["id"], "pattern": pattern, "script": found[0].get("script")}

    def is_applied(self, state):
        return state["script"] is None

    def desired(self, state):
        return dict(state, script=None)

    def same(self, a, b):
        return a == b

    def rest_equal(self, current, before):
        return True

    def write(self, state):
        self.client.set_route_script(self.zone, state["id"], state["pattern"], state["script"])

    def describe(self, before, after):
        call = f"PUT zones/{tail(self.zone)}/workers/routes/{tail(before['id'])}"
        return ({"call": call, "pattern": before["pattern"], "script": {"from": before["script"], "to": None}},
                {"call": call, "pattern": before["pattern"], "script": {"to": before["script"]}})

    def extra_guard(self, current, snapshot):
        return {}


DNS_TYPES = ("A", "AAAA", "CNAME")


def dns_record(raw):
    return {"id": raw.get("id"), "type": raw.get("type"), "name": raw.get("name"), "content": raw.get("content"),
            "ttl": raw.get("ttl"), "proxied": bool(raw.get("proxied")), "comment": raw.get("comment"),
            "tags": list(raw.get("tags") or [])}


def without_id(record):
    return {k: v for k, v in record.items() if k != "id"}


class DnsBase(LeverBase):
    """DNS record levers. State is {present, record}; the record is recorded in full."""
    needs_proxied = False

    def __init__(self, client, zone, host, params):
        self.client, self.zone, self.host = client, zone, host
        self.expect = params.get("expect_type")

    def read_lenient(self):
        found = [dns_record(r) for r in self.client.dns_records(self.zone, self.host) if r.get("type") in DNS_TYPES]
        require(len(found) <= 1, f"Expected at most one A/AAAA/CNAME record for {self.host}; found {len(found)}")
        return {"present": bool(found), "record": found[0] if found else None}

    def read(self):
        state = self.read_lenient()
        require(state["present"], f"No A/AAAA/CNAME record for {self.host}: nothing to act on "
                "(if this tool removed it earlier, restore with that run's snapshot)")
        kind = state["record"]["type"]
        require(kind == self.expect, f"DNS record type is {kind}, expected {self.expect}; refusing")
        return state

    def same(self, a, b):
        if a["present"] != b["present"]:
            return False
        return not a["present"] or without_id(a["record"]) == without_id(b["record"])

    def rest_equal(self, current, before):
        return True

    def write(self, state):
        """Make the record look like `state`: update in place, create (new id) or delete."""
        current = self.read_lenient()
        if state["present"]:
            body = without_id(state["record"])
            if current["present"]:
                self.client.update_dns_record(self.zone, current["record"]["id"], body)
            else:
                self.client.create_dns_record(self.zone, body)
        elif current["present"]:
            self.client.delete_dns_record(self.zone, current["record"]["id"])

    def extra_guard(self, current, snapshot):
        return {}


class DnsProxyFlipLever(DnsBase):
    name = "dns-proxy-flip"

    def gates(self, before):
        return [("accept_tls_change", "TLS TRUST CHANGE: Cloudflare terminates TLS instead of passing it through to "
                 "the TEE, and the existing tee.node Worker route goes LIVE, forwarding to the Phala -8000 origin "
                 "instead of the in-CVM ingress (nginx limits/CORS no longer in the path)")]

    def is_applied(self, state):
        return state["present"] and state["record"]["proxied"] is True

    def desired(self, state):
        # Cloudflare forces ttl to 1 (automatic) on a proxied record [INFERENCE].
        return {"present": True, "record": dict(state["record"], proxied=True, ttl=1)}

    def rest_equal(self, current, before):
        keys = ("type", "name", "content", "comment", "tags")
        return current["present"] and all(current["record"][k] == before["record"][k] for k in keys)

    def warnings(self, before):
        return ["Does not stop traffic by itself: it makes the WAF rule / Worker route live. Follow with the `waf` "
                "lever to block.", "Changes TLS trust and the serving path (see gate); verify clients and "
                "attestation flows that rely on the TEE certificate first.",
                "dstack-ingress holds a Cloudflare DNS token and may rewrite this record when it restarts "
                "[INFERENCE]; re-run verify after any CVM restart."]

    def describe(self, before, after):
        rec, new = before["record"], after["record"]
        call = f"PATCH zones/{tail(self.zone)}/dns_records/{tail(rec['id'])}"
        return ({"call": call, "type": rec["type"], "proxied": {"from": rec["proxied"], "to": new["proxied"]},
                 "ttl": {"from": rec["ttl"], "to": new["ttl"]}, "content": rec["content"]},
                {"call": call, "restore": {"proxied": rec["proxied"], "ttl": rec["ttl"], "content": rec["content"]}})

    def verify_note(self, snapshot):
        return "TLS is now terminated by Cloudflare; tee.node is served by the Worker, not the in-CVM ingress"


class DnsRemoveLever(DnsBase):
    name = "dns-remove"

    @staticmethod
    def ttl_text(record):
        ttl = record["ttl"]
        if ttl == 1:
            return ("recorded TTL is 1 (automatic; typically about 300 s, 300 s for proxied records) "
                    "[INFERENCE]")
        return f"recorded TTL is {ttl} s"

    def gates(self, before):
        return [("i_understand_ttl", "NOT INSTANT: resolvers keep serving the old answer until their cache "
                 f"expires ({self.ttl_text(before['record'])}), so this takes minutes, not seconds")]

    def warnings(self, before):
        return [f"'Instant' does not apply: {self.ttl_text(before['record'])}; clients with a cached answer keep "
                "reaching the old target until it expires, and clients with the literal origin address are "
                "unaffected.",
                "tee.node becomes unresolvable for everyone once caches expire; node.* is not touched.",
                "dstack-ingress holds a Cloudflare DNS token and may re-create this record on restart [INFERENCE]."]

    def is_applied(self, state):
        return not state["present"]

    def desired(self, state):
        return {"present": False, "record": None}

    def describe(self, before, after):
        rec = before["record"]
        return ({"call": f"DELETE zones/{tail(self.zone)}/dns_records/{tail(rec['id'])}",
                 "record": without_id(rec), "recorded_ttl": rec["ttl"]},
                {"call": f"POST zones/{tail(self.zone)}/dns_records", "recreate": without_id(rec),
                 "note": "the re-created record gets a NEW id; every other field is identical"})


LEVERS = {c.name: c for c in (WafLever, SecurityLevelLever, RouteLever, DnsProxyFlipLever, DnsRemoveLever)}
DNS_LEVERS = {DnsProxyFlipLever.name, DnsRemoveLever.name}


# ---- shared reads and snapshot handling ----

def node_guard(client, zone, protect_host):
    routes = [r for r in client.worker_routes(zone) if str(r.get("pattern", "")).split("/", 1)[0] == protect_host]
    dns = [{k: r.get(k) for k in ("id", "type", "name", "content", "proxied", "ttl")}
           for r in client.dns_records(zone, protect_host)]
    return {"worker_routes": sorted(routes, key=canon), "dns_records": sorted(dns, key=canon)}


def host_proxied(client, zone, host):
    records = client.dns_records(zone, host)
    if not records:
        return None
    return any(r.get("proxied") for r in records)


def write_new_private(path, value):
    """Exclusive create, 0600, fsynced: never replaces the only record of previous values."""
    with open(path, "x", encoding="utf-8", opener=lambda p, f: os.open(p, f, 0o600)) as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def replace_private(path, value):
    directory = os.path.dirname(os.path.abspath(path))
    fd, name = tempfile.mkstemp(dir=directory, prefix=".snapshot-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(value, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    except BaseException:
        if os.path.exists(name):
            os.unlink(name)
        raise


def load_snapshot(path):
    info = os.lstat(path)
    require(stat.S_ISREG(info.st_mode), "Snapshot must be a regular file (symlinks refused)")
    require(not info.st_mode & 0o077, "Snapshot permissions must be 0600")
    with open(path, encoding="utf-8") as stream:
        snap = json.load(stream)
    require(isinstance(snap, dict) and snap.get("format") == SNAPSHOT_FORMAT and snap.get("lever") in LEVERS,
            "Unrecognised snapshot")
    return snap


def make_lever(client, snap):
    return LEVERS[snap["lever"]](client, snap["zone_id"], snap["host"], snap["params"])


def load_token(args):
    if args.token_file:
        info = os.lstat(args.token_file)
        require(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o077,
                "Token file must be a regular (non-symlink) file with mode 0600")
        token = Path(args.token_file).read_text(encoding="utf-8").strip()
    else:
        token = os.environ.get(args.token_env, "").strip()
    require(token and re.fullmatch(r"[\x21-\x7e]+", token),
            "Token missing or malformed (source: " + ("file" if args.token_file else f"env {args.token_env}") + ")")
    return token


def emit(value):
    print(json.dumps(value, indent=2))


# ---- plan ----

def build_plan(client, args):
    require(HOST_RE.fullmatch(args.host) and HOST_RE.fullmatch(args.protect_host), "Invalid hostname")
    require(re.fullmatch(r"[0-9a-f]{32}", args.zone_id), "Expected a 32-hex zone id")
    require(args.host != args.protect_host and not args.protect_host.endswith("." + args.host),
            "The target host must not be, or be a parent of, the protected host")
    params = {"action": args.action} if args.lever == "waf" else {}
    if args.lever in DNS_LEVERS:
        require(args.expect_type, "--expect-type {A,AAAA,CNAME} is required for DNS levers "
                "(refuses if the record has another type)")
        params = {"expect_type": args.expect_type}
    lever = LEVERS[args.lever](client, args.zone_id, args.host, params)
    before = lever.read()
    already = lever.is_applied(before)
    after = lever.desired(before)
    proxied = host_proxied(client, args.zone_id, args.host)
    blockers = []
    if lever.needs_proxied and proxied is not True:
        blockers.append(("allow_inert", "INERT: " + args.host + " is "
                         + ("DNS-only (grey cloud)" if proxied is False else "not found in DNS")
                         + "; Cloudflare never sees its traffic, so this lever would do nothing for it"))
    blockers += lever.gates(before)
    open_blockers = [m for flag, m in blockers if not getattr(args, flag)]
    change, undo = lever.describe(before, after)
    plan_hash = digest({"v": SNAPSHOT_FORMAT, "lever": args.lever, "zone": args.zone_id, "host": args.host,
                        "protect_host": args.protect_host, "params": params, "before": before, "after": after})
    doc = {"command": "plan", "lever": args.lever, "zone": tail(args.zone_id), "host": args.host,
           "protected_host": args.protect_host, "host_proxied": proxied, "already_applied": already,
           "change": change, "undo": undo, "blockers": open_blockers, "warnings": lever.warnings(before),
           "limits": LIMITS,
           "plan_hash": plan_hash,
           "apply_command": f"{PROG} apply --snapshot <new-0600-file> --confirm {plan_hash} <same flags as plan>",
           "undo_command": f"{PROG} undo --snapshot <that-file> --confirm {plan_hash}"}
    return lever, before, after, params, doc, plan_hash, open_blockers, already


def cmd_plan(args, client):
    doc = build_plan(client, args)[4]
    emit(doc)
    return 0


# ---- verify ----

def run_verify(client, snap, expect):
    lever = make_lever(client, snap)
    current = lever.read_lenient()
    guard_now = node_guard(client, snap["zone_id"], snap["protect_host"])
    if expect == "applied":
        checks = {"lever_applied": lever.is_applied(current),
                  "no_collateral_change": lever.rest_equal(current, snap["before"])}
        checks.update(lever.extra_guard(current, snap))
    else:
        checks = {"restored_to_recorded_prior_state": lever.same(current, snap["before"])}
    checks["node_routes_and_dns_untouched"] = guard_now == snap["guard"]
    report = {"command": "verify", "expect": expect, "lever": snap["lever"], "zone": tail(snap["zone_id"]),
              "host": snap["host"], "checks": checks, "ok": all(checks.values())}
    note = lever.verify_note(snap)
    if note and expect == "applied":
        report["note"] = note
    return report


def cmd_verify(args, client):
    report = run_verify(client, load_snapshot(args.snapshot), args.expect)
    emit(report)
    return 0 if report["ok"] else 4


# ---- apply ----

def cmd_apply(args, client):
    lever, before, after, params, doc, plan_hash, blockers, already = build_plan(client, args)
    doc["command"] = "apply"
    if already:
        doc["result"] = ("already applied; nothing changed. If this run did not create the lever, use the "
                         "snapshot of the run that did for undo")
        emit(doc)
        return 0
    if args.confirm is None:
        doc["result"] = "dry-run: nothing changed; pass --confirm <plan_hash> to execute"
        emit(doc)
        return 0
    require(args.confirm == plan_hash, "--confirm does not match the current plan hash (state changed since "
            "plan, or wrong hash); re-run plan")
    require(not blockers, "; ".join(blockers) + ". Re-run with the matching --allow-* flag if intended")
    guard = node_guard(client, args.zone_id, args.protect_host)
    snap = {"format": SNAPSHOT_FORMAT, "status": "pending", "created_at_utc": now(), "plan_hash": plan_hash,
            "lever": args.lever, "zone_id": args.zone_id, "host": args.host, "protect_host": args.protect_host,
            "params": params, "before": before, "after": after, "guard": guard}
    try:
        write_new_private(args.snapshot, snap)  # BEFORE any change
    except FileExistsError:
        raise Refused("Snapshot path already exists; refusing to overwrite a prior rollback record") from None
    try:
        lever.write(after)
    except Exception as error:
        print(f"APPLY FAILED ({type(error).__name__}). The change may be partial or absent; a snapshot of the "
              f"prior state exists at {args.snapshot} (status pending). Recovery: run "
              f"`{PROG} undo --snapshot {args.snapshot} --confirm {plan_hash}` (dry-run first without --confirm); "
              "it restores the prior state, or reports nothing to undo.", file=sys.stderr)
        raise
    snap["status"] = "applied"
    snap["applied_at_utc"] = now()
    replace_private(args.snapshot, snap)
    doc["result"] = "applied; snapshot written at " + str(args.snapshot)
    emit(doc)
    report = run_verify(client, snap, "applied")
    emit(report)
    return 0 if report["ok"] else 4


# ---- undo ----

def cmd_undo(args, client):
    snap = load_snapshot(args.snapshot)
    lever = make_lever(client, snap)
    current = lever.read_lenient()
    out = {"command": "undo", "lever": snap["lever"], "zone": tail(snap["zone_id"]), "host": snap["host"],
           "plan_hash": snap["plan_hash"]}
    out["restore"] = lever.describe(snap["before"], snap["after"])[1]
    if lever.same(current, snap["before"]):
        if snap["status"] == "pending":
            snap["status"] = "aborted"
            replace_private(args.snapshot, snap)
        out["result"] = "already at the recorded prior state; nothing to undo"
        emit(out)
        return 0
    at_after = lever.is_applied(current) and lever.rest_equal(current, snap["before"])
    drift = not at_after
    out["drift"] = drift
    if drift and not args.force_drift:
        out["result"] = ("REFUSED: current state is neither the recorded prior state nor the state this tool "
                         "applied (someone changed it). Inspect; use --force-drift to overwrite")
        emit(out)
        return 1
    if args.confirm is None:
        out["result"] = "dry-run: nothing changed; pass --confirm <plan_hash> to execute"
        emit(out)
        return 0
    require(args.confirm == snap["plan_hash"], "--confirm does not match the snapshot's plan hash")
    if drift:
        snap.setdefault("forced_undo", []).append({"at_utc": now(), "overwrote": current})
        replace_private(args.snapshot, snap)  # record what is about to be overwritten
    lever.write(snap["before"])
    snap["status"] = "undone"
    snap["undone_at_utc"] = now()
    replace_private(args.snapshot, snap)
    out["result"] = "restored"
    emit(out)
    report = run_verify(client, snap, "undone")
    emit(report)
    return 0 if report["ok"] else 4


# ---- CLI ----

def build_parser():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    common = argparse.ArgumentParser(add_help=False)
    source = common.add_mutually_exclusive_group(required=True)
    source.add_argument("--token-file", help="Path to a 0600 file holding the Cloudflare API token")
    source.add_argument("--token-env", help="NAME of an environment variable holding the token (never its value)")
    target = argparse.ArgumentParser(add_help=False)
    target.add_argument("--zone-id", required=True, help="32-hex Cloudflare zone id")
    target.add_argument("--host", default="tee.node.tinycloud.xyz", help="Hostname to switch off")
    target.add_argument("--protect-host", default="node.tinycloud.xyz", help="Hostname that must stay untouched")
    target.add_argument("--lever", choices=sorted(LEVERS), default="waf")
    target.add_argument("--action", choices=WAF_ACTIONS, default="block", help="waf lever only")
    target.add_argument("--allow-inert", action="store_true", help="Apply even if the host is not proxied (drills)")
    target.add_argument("--allow-zone-wide", action="store_true", help="Required for the security-level lever")
    target.add_argument("--allow-no-block", action="store_true", help="Required for the worker-route lever")
    target.add_argument("--accept-tls-change", action="store_true", help="Required for the dns-proxy-flip lever")
    target.add_argument("--i-understand-ttl", action="store_true", help="Required for the dns-remove lever (not instant)")
    target.add_argument("--expect-type", choices=DNS_TYPES, help="DNS levers: the record type that must be found")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("plan", parents=[common, target], help="Read-only: print exact change, undo and plan hash")
    apply = sub.add_parser("apply", parents=[common, target], help="Dry-run unless --confirm <plan-hash>")
    apply.add_argument("--snapshot", type=Path, required=True, help="NEW 0600 rollback file (created first)")
    apply.add_argument("--confirm", help="plan_hash printed by plan")
    undo = sub.add_parser("undo", parents=[common], help="Restore the snapshot; dry-run unless --confirm")
    undo.add_argument("--snapshot", type=Path, required=True)
    undo.add_argument("--confirm", help="plan_hash recorded in the snapshot")
    undo.add_argument("--force-drift", action="store_true", help="Overwrite a state this tool did not create")
    verify = sub.add_parser("verify", parents=[common], help="Re-read and check lever state and node guard")
    verify.add_argument("--snapshot", type=Path, required=True)
    verify.add_argument("--expect", choices=("applied", "undone"), default="applied")
    return parser


COMMANDS = {"plan": cmd_plan, "apply": cmd_apply, "undo": cmd_undo, "verify": cmd_verify}


def main(argv=None, client_factory=None):
    args = build_parser().parse_args(argv)
    token = None
    try:
        token = load_token(args)
        client = (client_factory or CloudflareClient)(token)
        return COMMANDS[args.cmd](args, client)
    except (Refused, CfError, OSError, ValueError, KeyError, TypeError) as error:
        detail = str(error) if isinstance(error, (Refused, CfError)) else type(error).__name__
        if token:
            detail = detail.replace(token, "[redacted]")
        kind = "refused" if isinstance(error, Refused) else "failed"
        print(f"ingress-cf-switch {kind}: {detail}", file=sys.stderr)
        return 1 if isinstance(error, Refused) else 3
    except Exception as error:  # apply already printed its recovery instruction
        print(f"ingress-cf-switch failed: {type(error).__name__}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
