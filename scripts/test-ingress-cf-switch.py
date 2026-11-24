#!/usr/bin/env python3
"""Contracts for ingress-cf-switch.py. Fakes only: no network, no Cloudflare, no real token."""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
from urllib.error import HTTPError

SCRIPT = Path(__file__).with_name("ingress-cf-switch.py")
spec = importlib.util.spec_from_file_location("ingress_cf_switch", SCRIPT)
sw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sw)

ZONE = "29b3a489c28c19707f8a9dd91da9dc42"
HOST = "tee.node.tinycloud.xyz"
NODE = "node.tinycloud.xyz"
TOKEN = "cfpat-" + "Zq8" * 12  # fake, test-only
ENV = "TC_CF_SWITCH_TEST_TOKEN"
MUTATORS = {"create_entrypoint", "add_rule", "delete_rule", "set_security_level", "set_route_script"}


class FakeCF:
    """Records every call; models just enough Cloudflare behaviour (server-assigned rule ids)."""

    def __init__(self):
        self.rules = [
            {"id": "r-aaaa1111", "version": "3", "last_updated": "2026-11-01T00:00:00Z", "action": "skip",
             "expression": '(ip.src eq 192.0.2.7)', "description": "allow monitor", "enabled": True},
            {"id": "r-bbbb2222", "version": "1", "last_updated": "2026-11-02T00:00:00Z", "action": "block",
             "expression": '(http.host eq "old.example.test")', "description": "legacy", "enabled": False},
        ]
        self.level = "medium"
        self.routes = [
            {"id": "route-node-9999", "pattern": f"{NODE}/*", "script": "tinycloud-tee-proxy"},
            {"id": "route-tee-8888", "pattern": f"{HOST}/*", "script": "tinycloud-tee-proxy"},
        ]
        self.dns = [
            {"id": "dns-node-1", "type": "CNAME", "name": NODE, "content": "x.example.test", "proxied": True, "ttl": 1},
            {"id": "dns-tee-2", "type": "CNAME", "name": HOST, "content": "y.example.test", "proxied": True, "ttl": 1},
        ]
        self.calls = []
        self.before_put = None  # hook run at the start of a rule write
        self.fail_put = False
        self.ruleset_id = "rs-7777"
        self._n = 0

    def writes(self):
        return [c for c in self.calls if c[0] in MUTATORS]

    def security_level(self, zone):
        self.calls.append(("security_level", zone))
        return self.level

    def set_security_level(self, zone, value):
        self.calls.append(("set_security_level", zone, value))
        self.level = value

    def entrypoint(self, zone):
        self.calls.append(("entrypoint", zone))
        if self.rules is None:
            return None
        return {"id": self.ruleset_id, "rules": copy.deepcopy(self.rules)}

    def _hooks(self, op):
        if self.before_put:
            self.before_put()
        if self.fail_put:
            raise sw.CfError(f"{op}: HTTP 500 Authorization: Bearer {TOKEN}")

    def _assign(self, rule):
        rule = copy.deepcopy(rule)
        if "id" not in rule:
            self._n += 1
            rule.update(id=f"r-new{self._n:04d}", version="1", last_updated="2026-11-24T00:00:00Z")
        return rule

    def create_entrypoint(self, zone, rules):
        self.calls.append(("create_entrypoint", zone, copy.deepcopy(rules)))
        self._hooks("create_entrypoint")
        self.rules = [self._assign(r) for r in rules]

    def add_rule(self, zone, ruleset_id, rule, index):
        self.calls.append(("add_rule", zone, ruleset_id, copy.deepcopy(rule), index))
        self._hooks("add_rule")
        self.rules.insert(index - 1, self._assign(rule))

    def delete_rule(self, zone, ruleset_id, rule_id):
        self.calls.append(("delete_rule", zone, ruleset_id, rule_id))
        self.rules = [r for r in self.rules if r["id"] != rule_id]

    def worker_routes(self, zone):
        self.calls.append(("worker_routes", zone))
        return copy.deepcopy(self.routes)

    def set_route_script(self, zone, route_id, pattern, script):
        self.calls.append(("set_route_script", zone, route_id, pattern, script))
        for route in self.routes:
            if route["id"] == route_id:
                route["script"] = script

    def dns_records(self, zone, name):
        self.calls.append(("dns_records", zone, name))
        return [copy.deepcopy(r) for r in self.dns if r["name"] == name]

    def update_dns_record(self, zone, record_id, body):
        self.calls.append(("update_dns_record", zone, record_id, copy.deepcopy(body)))
        for record in self.dns:
            if record["id"] == record_id:
                record.update(copy.deepcopy(body))
                if body.get("proxied") is True and "ttl" not in body:
                    record["ttl"] = 1  # Cloudflare sets automatic ttl on proxied records [INFERENCE]

    def create_dns_record(self, zone, body):
        self.calls.append(("create_dns_record", zone, copy.deepcopy(body)))
        self._n += 1
        self.dns.append(dict(copy.deepcopy(body), id=f"dns-new-{self._n}"))

    def delete_dns_record(self, zone, record_id):
        self.calls.append(("delete_dns_record", zone, record_id))
        self.dns = [r for r in self.dns if r["id"] != record_id]


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.snap = self.dir / "snap.json"
        self.fake = FakeCF()
        patcher = mock.patch.dict(os.environ, {ENV: TOKEN})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.outputs = []

    def run_cli(self, *args, fake=None):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = sw.main([*args[:1], "--token-env", ENV, *args[1:]], client_factory=lambda token: fake or self.fake)
        self.outputs += [out.getvalue(), err.getvalue()]
        return code, out.getvalue(), err.getvalue()

    @staticmethod
    def docs(text):
        decoder, pos, found = json.JSONDecoder(), 0, []
        while pos < len(text):
            if text[pos].isspace():
                pos += 1
                continue
            value, pos = decoder.raw_decode(text, pos)
            found.append(value)
        return found

    def target(self, *extra):
        return ["--zone-id", ZONE, *extra]

    def plan(self, *extra):
        code, out, _ = self.run_cli("plan", *self.target(*extra))
        self.assertEqual(code, 0)
        return self.docs(out)[0]

    def apply(self, plan_hash, *extra, snap=None):
        return self.run_cli("apply", *self.target(*extra), "--snapshot", str(snap or self.snap),
                            *(["--confirm", plan_hash] if plan_hash else []))

    def undo(self, *extra):
        return self.run_cli("undo", "--snapshot", str(self.snap), *extra)

    def token(self, snap=None):
        """The undo token apply wrote into the snapshot (it is also printed by apply and the undo dry-run)."""
        return json.loads(Path(snap or self.snap).read_text())["undo_token"]

    def undo_dry_run(self, snap=None, *extra):
        code, out, err = self.run_cli("undo", "--snapshot", str(snap or self.snap), *extra)
        self.assertEqual(code, 0, err)
        return self.docs(out)[0]

    def applied(self):
        h = self.plan()["plan_hash"]
        code, out, err = self.apply(h)
        self.assertEqual(code, 0, err)
        return h


class WafLeverTest(Base):
    def test_plan_is_read_only_and_exact(self):
        before = copy.deepcopy(self.fake.rules)
        doc = self.plan()
        self.assertEqual(self.fake.writes(), [])
        self.assertEqual(self.fake.rules, before)
        self.assertEqual(doc["change"]["rule"], {"action": "block", "expression": f'(http.host eq "{HOST}")',
                                                 "description": sw.MARKER, "enabled": True})
        self.assertEqual(doc["change"]["call"], f"POST zones/…{ZONE[-4:]}/rulesets/…7777/rules (position index 1)")
        self.assertEqual(doc["undo"]["expected_remaining_rules"]["count"], 2)
        self.assertIn("only the rule this apply created", doc["undo"]["removes"])
        self.assertEqual(doc["blockers"], [])
        self.assertRegex(doc["plan_hash"], r"^[0-9a-f]{64}$")
        self.assertEqual(doc["zone"], "…" + ZONE[-4:])
        self.assertNotIn(ZONE, json.dumps(doc))  # ids are printed as last-4 only
        self.assertEqual(doc["plan_hash"], self.plan()["plan_hash"])  # deterministic

    def test_apply_without_or_with_wrong_confirm_changes_nothing(self):
        code, out, _ = self.apply(None)
        self.assertEqual(code, 0)
        self.assertIn("dry-run", self.docs(out)[0]["result"])
        code, _, err = self.apply("0" * 64)
        self.assertEqual(code, 1)
        self.assertIn("--confirm", err)
        self.assertEqual(self.fake.writes(), [])
        self.assertFalse(self.snap.exists())

    def test_apply_writes_private_snapshot_before_the_change(self):
        original = copy.deepcopy(self.fake.rules)
        seen = {}

        def at_put():
            seen["exists"] = self.snap.exists()
            seen["mode"] = stat.S_IMODE(self.snap.stat().st_mode)
            saved = json.loads(self.snap.read_text())
            seen["status"], seen["before"] = saved["status"], saved["before"]["rules"]

        self.fake.before_put = at_put
        h = self.applied()
        self.assertEqual(seen, {"exists": True, "mode": 0o600, "status": "pending", "before": original})
        saved = json.loads(self.snap.read_text())
        self.assertEqual(saved["status"], "applied")
        self.assertEqual(stat.S_IMODE(self.snap.stat().st_mode), 0o600)
        self.assertEqual(saved["before"]["rules"], original)  # exact values, ids and versions included
        self.assertEqual(saved["plan_hash"], h)
        self.assertEqual([r["description"] for r in self.fake.rules], [sw.MARKER, "allow monitor", "legacy"])
        self.assertEqual(self.fake.rules[0]["expression"], f'(http.host eq "{HOST}")')

    def test_apply_runs_verify_and_it_passes(self):
        h = self.plan()["plan_hash"]
        _, out, _ = self.apply(h)
        report = self.docs(out)[-1]
        self.assertEqual(report["command"], "verify")
        self.assertTrue(report["ok"], report)
        self.assertTrue(all(report["checks"].values()))

    def test_apply_twice_is_idempotent_and_keeps_first_snapshot(self):
        self.applied()
        first = self.snap.read_bytes()
        rules = copy.deepcopy(self.fake.rules)
        writes = len(self.fake.writes())
        second = self.dir / "snap2.json"
        h2 = self.plan()["plan_hash"]
        code, out, _ = self.apply(h2, snap=second)
        self.assertEqual(code, 0)
        self.assertIn("already applied", self.docs(out)[0]["result"])
        code, out, _ = self.apply(None, snap=second)
        self.assertEqual(code, 0)
        self.assertEqual(len(self.fake.writes()), writes)
        self.assertEqual(self.fake.rules, rules)
        self.assertFalse(second.exists())
        self.assertEqual(self.snap.read_bytes(), first)

    def test_apply_refuses_to_overwrite_existing_snapshot_path(self):
        self.snap.write_text("keep me")
        code, _, err = self.apply(self.plan()["plan_hash"])
        self.assertEqual(code, 1)
        self.assertEqual(self.snap.read_text(), "keep me")
        self.assertEqual(self.fake.writes(), [])

    def test_state_change_between_plan_and_apply_invalidates_the_hash(self):
        h = self.plan()["plan_hash"]
        self.fake.rules.append({"id": "r-cccc3333", "version": "1", "action": "log", "expression": "true",
                                "description": "someone else", "enabled": True})
        code, _, err = self.apply(h)
        self.assertEqual(code, 1)
        self.assertEqual(self.fake.writes(), [])

    def test_undo_restores_byte_identical_prior_state(self):
        original = json.dumps(self.fake.rules)
        h = self.applied()
        self.assertNotEqual(json.dumps(self.fake.rules), original)
        code, out, _ = self.undo()  # dry-run
        self.assertEqual(code, 0)
        self.assertIn("dry-run", self.docs(out)[0]["result"])
        self.assertNotEqual(json.dumps(self.fake.rules), original)
        code, out, err = self.undo("--confirm", self.token())
        self.assertEqual(code, 0, err)
        self.assertEqual(json.dumps(self.fake.rules), original)
        self.assertEqual(self.fake.calls[-1][0], "dns_records")
        deletes = [c for c in self.fake.calls if c[0] == "delete_rule"]
        self.assertEqual(len(deletes), 1)  # only our rule is deleted; no list is rewritten
        self.assertEqual(deletes[0][3], "r-new0001")
        self.assertTrue(self.docs(out)[-1]["ok"])
        self.assertEqual(json.loads(self.snap.read_text())["status"], "undone")
        code, _, err = self.undo("--confirm", self.token())  # a finished snapshot can not be replayed
        self.assertEqual(code, 1)
        self.assertIn("already undone", err)

    def test_undo_restores_absent_entrypoint_as_empty_rules(self):
        self.fake.rules = None  # entrypoint ruleset does not exist yet
        h = self.applied()
        self.assertEqual(len(self.fake.rules), 1)
        code, _, err = self.undo("--confirm", self.token())
        self.assertEqual(code, 0, err)
        self.assertEqual(self.fake.rules, [])

    def test_drift_is_refused_then_forced_with_record(self):
        h = self.applied()
        added = {"id": "r-dddd4444", "version": "1", "action": "log", "expression": "(true)",
                 "description": "added by someone else", "enabled": True}
        self.fake.rules.append(added)
        snapshot_before = self.snap.read_bytes()
        code, out, _ = self.undo("--confirm", self.token())
        self.assertEqual(code, 1)
        self.assertIn("REFUSED", self.docs(out)[0]["result"])
        self.assertIn(added, self.fake.rules)
        self.assertEqual(self.snap.read_bytes(), snapshot_before)
        code, out, err = self.undo("--confirm", self.token(), "--force-drift")
        self.assertEqual(code, 4, err)  # ours removed; verify says the list still differs from the recorded one
        self.assertEqual([r["id"] for r in self.fake.rules], ["r-aaaa1111", "r-bbbb2222", "r-dddd4444"])
        forced = json.loads(self.snap.read_text())["forced_undo"]
        self.assertEqual(len(forced), 1)
        self.assertIn(added, forced[0]["overwrote"]["rules"])  # the state at the time is recorded
        self.assertIn("by design", self.docs(out)[-1]["note"])  # exit 4 here is expected, and says so

    def test_edited_lever_rule_counts_as_drift(self):
        h = self.applied()
        self.fake.rules[0]["action"] = "log"
        code, _, _ = self.undo("--confirm", self.token())
        self.assertEqual(code, 1)
        self.assertEqual(self.fake.rules[0]["action"], "log")

    def test_failed_api_call_mid_apply_leaves_snapshot_and_recovery_instruction(self):
        original = copy.deepcopy(self.fake.rules)
        self.fake.fail_put = True
        h = self.plan()["plan_hash"]
        code, out, err = self.apply(h)
        self.assertEqual(code, 3)
        self.assertEqual(self.fake.rules, original)
        saved = json.loads(self.snap.read_text())
        self.assertEqual(saved["status"], "pending")
        self.assertEqual(saved["before"]["rules"], original)
        self.assertIn("APPLY FAILED", err)
        self.assertIn(f"undo --snapshot {self.snap}", err)
        self.assertIn("prior state", err)
        self.fake.fail_put = False
        code, out, _ = self.undo("--confirm", self.token())
        self.assertEqual(code, 0)
        self.assertIn("nothing to undo", self.docs(out)[0]["result"])
        self.assertEqual(json.loads(self.snap.read_text())["status"], "aborted")

    def test_token_never_appears_in_output_or_files(self):
        self.fake.fail_put = True  # the fake's error message embeds the token on purpose
        h = self.plan()["plan_hash"]
        self.apply(h)
        self.fake.fail_put = False
        self.snap.unlink()
        self.applied()
        self.undo("--confirm", self.token())
        self.run_cli("verify", "--snapshot", str(self.snap), "--expect", "undone")
        for text in self.outputs:
            self.assertNotIn(TOKEN, text)
            self.assertNotIn("Authorization: Bearer cf", text)
        for path in self.dir.rglob("*"):
            if path.is_file():
                self.assertNotIn(TOKEN, path.read_text())

    def test_node_host_is_untouched_and_verify_catches_changes(self):
        node_routes = [r for r in self.fake.routes if r["pattern"].startswith(NODE)]
        node_dns = [r for r in self.fake.dns if r["name"] == NODE]
        h = self.applied()
        self.assertEqual([r for r in self.fake.routes if r["pattern"].startswith(NODE)], node_routes)
        self.assertEqual([r for r in self.fake.dns if r["name"] == NODE], node_dns)
        self.assertNotIn(f'"{NODE}"', self.fake.rules[0]["expression"])
        self.assertEqual(self.fake.writes()[0][0], "add_rule")
        code, out, _ = self.run_cli("verify", "--snapshot", str(self.snap))
        self.assertEqual(code, 0)
        self.assertTrue(self.docs(out)[0]["checks"]["node_routes_and_dns_untouched"])
        self.assertTrue(self.docs(out)[0]["checks"]["our_rule_does_not_match_protected_host"])
        self.fake.routes[0]["script"] = None  # someone disables the node.* Worker
        code, out, _ = self.run_cli("verify", "--snapshot", str(self.snap))
        self.assertEqual(code, 4)
        self.assertFalse(self.docs(out)[0]["checks"]["node_routes_and_dns_untouched"])

    def test_target_may_not_be_or_contain_the_protected_host(self):
        for host in (NODE, "tinycloud.xyz"):
            code, _, err = self.run_cli("plan", *self.target("--host", host))
            self.assertEqual(code, 1, host)
            self.assertIn("protected host", err)
        self.assertEqual(self.fake.writes(), [])

    def test_inert_host_is_refused_unless_allowed(self):
        self.fake.dns[1]["proxied"] = False  # DNS-only, as tee.node was at the 2026-10-16 capture
        doc = self.plan()
        self.assertFalse(doc["host_proxied"])
        self.assertIn("INERT", doc["blockers"][0])
        code, _, err = self.apply(doc["plan_hash"])
        self.assertEqual(code, 1)
        self.assertIn("INERT", err)
        self.assertEqual(self.fake.writes(), [])
        self.assertFalse(self.snap.exists())
        code, _, err = self.apply(doc["plan_hash"], "--allow-inert")
        self.assertEqual(code, 0, err)

    def test_missing_dns_record_is_treated_as_inert(self):
        self.fake.dns = [r for r in self.fake.dns if r["name"] != HOST]
        self.assertIn("not found in DNS", self.plan()["blockers"][0])

    def test_foreign_rule_with_our_marker_but_other_settings_is_refused(self):
        self.fake.rules.insert(0, {"id": "r-eeee5555", "action": "log", "expression": "(true)",
                                   "description": sw.MARKER, "enabled": True})
        code, _, err = self.run_cli("plan", *self.target())
        self.assertEqual(code, 1)
        self.assertIn("different settings", err)

    def test_selectable_challenge_action(self):
        doc = self.plan("--action", "managed_challenge")
        self.assertEqual(doc["change"]["rule"]["action"], "managed_challenge")
        self.assertNotEqual(doc["plan_hash"], self.plan()["plan_hash"])


class OtherLeversTest(Base):
    def test_security_level_is_zone_wide_gated_and_exactly_restored(self):
        doc = self.plan("--lever", "security-level")
        self.assertIn("ZONE-WIDE", doc["blockers"][0])
        code, _, err = self.apply(doc["plan_hash"], "--lever", "security-level")
        self.assertEqual(code, 1)
        self.assertEqual(self.fake.writes(), [])
        code, out, err = self.apply(doc["plan_hash"], "--lever", "security-level", "--allow-zone-wide")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.fake.level, "under_attack")
        self.assertIn("zone-wide", self.docs(out)[-1]["note"])
        code, _, err = self.undo("--confirm", self.token())
        self.assertEqual(code, 0, err)
        self.assertEqual(self.fake.level, "medium")
        self.assertEqual([c for c in self.fake.calls if c[0] == "set_security_level"],
                         [("set_security_level", ZONE, "under_attack"), ("set_security_level", ZONE, "medium")])

    def test_worker_route_lever_is_gated_keeps_node_route_and_restores_script(self):
        before = copy.deepcopy(self.fake.routes)
        doc = self.plan("--lever", "worker-route")
        self.assertIn("DOES NOT BLOCK", doc["blockers"][0])
        code, _, _ = self.apply(doc["plan_hash"], "--lever", "worker-route")
        self.assertEqual(code, 1)
        self.assertEqual(self.fake.routes, before)
        code, _, err = self.apply(doc["plan_hash"], "--lever", "worker-route", "--allow-no-block")
        self.assertEqual(code, 0, err)
        self.assertIsNone(self.fake.routes[1]["script"])
        self.assertEqual(self.fake.routes[0], before[0])  # node.* route untouched
        self.assertEqual([c[2] for c in self.fake.writes()], ["route-tee-8888"])
        code, _, err = self.undo("--confirm", self.token())
        self.assertEqual(code, 0, err)
        self.assertEqual(json.dumps(self.fake.routes), json.dumps(before))


class DnsLeversTest(Base):
    FLIP = ("--lever", "dns-proxy-flip", "--expect-type", "CNAME")
    REMOVE = ("--lever", "dns-remove", "--expect-type", "CNAME")

    def setUp(self):
        super().setUp()
        self.fake.dns[1].update(proxied=False, ttl=300, comment="managed by dstack-ingress", tags=["env:prod"],
                                modified_on="2026-11-03T00:00:00Z")
        self.original = json.dumps(self.fake.dns)
        self.node_record = copy.deepcopy(self.fake.dns[0])

    def tee(self):
        return [r for r in self.fake.dns if r["name"] == HOST]

    def dns_writes(self):
        return [c for c in self.fake.calls if c[0] in ("update_dns_record", "create_dns_record", "delete_dns_record")]

    def test_flip_plan_is_read_only_exact_and_warns_about_tls(self):
        doc = self.plan(*self.FLIP)
        self.assertEqual(self.fake.writes(), [])
        self.assertEqual(self.dns_writes(), [])
        self.assertEqual(doc["change"]["proxied"], {"from": False, "to": True})
        self.assertEqual(doc["change"]["sends"], {"proxied": True})
        self.assertEqual(doc["undo"]["sends"], {"proxied": False, "ttl": 300})
        self.assertEqual(doc["undo"]["never_written"], ["type", "name", "content", "comment", "tags"])
        self.assertIn("edge certificate", doc["blockers"][0])
        self.assertIn("*.tinycloud.xyz", doc["blockers"][0])
        self.assertEqual(len(doc["blockers"]), 1)
        self.assertIn("TLS TRUST CHANGE", doc["blockers"][0])
        self.assertIn("Cloudflare terminates TLS", doc["blockers"][0])
        self.assertTrue(any("Does not stop traffic" in w for w in doc["warnings"]))
        self.assertNotIn("INERT", json.dumps(doc["blockers"]))  # DNS-only is the precondition here

    def test_flip_apply_gated_then_exact_undo(self):
        h = self.plan(*self.FLIP)["plan_hash"]
        code, _, err = self.apply(h, *self.FLIP)
        self.assertEqual(code, 1)
        self.assertIn("TLS TRUST CHANGE", err)
        self.assertEqual(self.dns_writes(), [])
        self.assertFalse(self.snap.exists())
        code, out, err = self.apply(h, *self.FLIP, "--accept-tls-change")
        self.assertEqual(code, 0, err)
        self.assertTrue(self.docs(out)[-1]["ok"])
        self.assertEqual((self.tee()[0]["proxied"], self.tee()[0]["ttl"]), (True, 1))
        saved = json.loads(self.snap.read_text())["before"]["record"]
        self.assertEqual(saved, {"id": "dns-tee-2", "type": "CNAME", "name": HOST, "content": "y.example.test",
                                 "ttl": 300, "proxied": False, "comment": "managed by dstack-ingress",
                                 "tags": ["env:prod"]})
        self.assertEqual(self.fake.dns[0], self.node_record)
        code, _, err = self.undo("--confirm", self.token())
        self.assertEqual(code, 0, err)
        self.assertEqual(json.dumps(self.fake.dns), self.original)  # byte-identical
        updates = [c[3] for c in self.fake.calls if c[0] == "update_dns_record"]
        self.assertEqual(updates, [{"proxied": True}, {"proxied": False, "ttl": 300}])  # nothing else is sent

    def test_flip_apply_twice_is_idempotent(self):
        h = self.plan(*self.FLIP)["plan_hash"]
        self.apply(h, *self.FLIP, "--accept-tls-change")
        writes = len(self.dns_writes())
        second = self.dir / "second.json"
        code, out, _ = self.apply(self.plan(*self.FLIP)["plan_hash"], *self.FLIP, "--accept-tls-change", snap=second)
        self.assertEqual(code, 0)
        self.assertIn("already applied", self.docs(out)[0]["result"])
        self.assertEqual(len(self.dns_writes()), writes)
        self.assertFalse(second.exists())

    def test_flip_after_a_rewrite_by_others_undo_restores_only_proxied_and_ttl(self):
        h = self.plan(*self.FLIP)["plan_hash"]
        self.apply(h, *self.FLIP, "--accept-tls-change")
        self.fake.dns[1]["content"] = "someone-else.example.test"  # e.g. dstack-ingress rewrote the target
        self.fake.dns[1]["comment"] = "rewritten"
        code, out, err = self.undo("--confirm", self.token())  # not drift: only proxied/ttl are judged
        self.assertEqual(code, 0, err)
        self.assertEqual(self.docs(out)[0]["unmanaged_changes_reported_not_written"], ["content", "comment"])
        self.assertEqual(self.docs(out)[-1]["unmanaged_changes_reported_not_written"], ["content", "comment"])
        self.assertEqual(self.tee()[0]["content"], "someone-else.example.test")  # never written back
        self.assertEqual(self.tee()[0]["comment"], "rewritten")
        self.assertEqual((self.tee()[0]["proxied"], self.tee()[0]["ttl"]), (False, 300))
        self.assertEqual([c[3] for c in self.dns_writes()], [{"proxied": True}, {"proxied": False, "ttl": 300}])
        self.assertTrue(self.docs(out)[-1]["ok"])

    def test_flip_drift_on_proxied_or_ttl_is_refused_then_forced_and_recorded(self):
        h = self.plan(*self.FLIP)["plan_hash"]
        self.apply(h, *self.FLIP, "--accept-tls-change")
        self.fake.dns[1].update(proxied=False, ttl=120)  # someone flipped it back with another ttl
        code, out, _ = self.undo("--confirm", self.token())
        self.assertEqual(code, 1)
        self.assertEqual(self.fake.dns[1]["ttl"], 120)
        code, _, err = self.undo("--confirm", self.token(), "--force-drift")
        self.assertEqual(code, 0, err)
        self.assertEqual(json.dumps(self.fake.dns), self.original)
        forced = json.loads(self.snap.read_text())["forced_undo"]
        self.assertEqual(forced[0]["overwrote"]["record"]["ttl"], 120)

    def test_dns_write_refuses_a_record_other_than_the_planned_one(self):
        lever = sw.DnsRemoveLever(self.fake, ZONE, HOST, {"expect_type": "CNAME"})
        planned = lever.read()
        after = lever.desired(planned)
        self.fake.dns[1]["id"] = "dns-replaced-by-someone"
        with self.assertRaises(sw.Refused) as raised:
            lever.write(after, planned)
        self.assertIn("Next step", str(raised.exception))
        self.assertEqual(self.dns_writes(), [])

    def test_record_settings_are_snapshotted_and_recreated(self):
        self.fake.dns[1]["settings"] = {"flatten_cname": True}
        h = self.plan(*self.REMOVE)["plan_hash"]
        self.apply(h, *self.REMOVE, "--i-understand-ttl")
        self.assertEqual(json.loads(self.snap.read_text())["before"]["record"]["settings"], {"flatten_cname": True})
        self.undo("--confirm", self.token())
        self.assertEqual(self.tee()[0]["settings"], {"flatten_cname": True})

    def test_remove_plan_states_ttl_and_that_it_is_not_instant(self):
        doc = self.plan(*self.REMOVE)
        self.assertEqual(doc["change"]["recorded_ttl"], 300)
        self.assertIn("recorded TTL is 300 s", doc["blockers"][0])
        self.assertIn("minutes, not seconds", doc["blockers"][0])
        self.assertTrue(any("'Instant' does not apply" in w and "300 s" in w for w in doc["warnings"]))
        self.assertEqual(doc["undo"]["recreate"]["comment"], "managed by dstack-ingress")
        self.assertEqual(self.dns_writes(), [])
        self.fake.dns[1]["ttl"] = 1
        self.assertIn("automatic", self.plan(*self.REMOVE)["blockers"][0])

    def test_remove_requires_ttl_acknowledgement(self):
        h = self.plan(*self.REMOVE)["plan_hash"]
        code, _, err = self.apply(h, *self.REMOVE)
        self.assertEqual(code, 1)
        self.assertIn("NOT INSTANT", err)
        self.assertEqual(self.dns_writes(), [])
        self.assertFalse(self.snap.exists())

    def test_remove_snapshots_full_record_and_undo_recreates_it_identically(self):
        h = self.plan(*self.REMOVE)["plan_hash"]
        seen = {}
        orig_delete = self.fake.delete_dns_record

        def delete(zone, record_id):
            seen["snapshot_first"] = json.loads(self.snap.read_text())["before"]["record"]
            orig_delete(zone, record_id)

        self.fake.delete_dns_record = delete
        code, out, err = self.apply(h, *self.REMOVE, "--i-understand-ttl")
        self.assertEqual(code, 0, err)
        self.assertEqual(seen["snapshot_first"]["tags"], ["env:prod"])
        self.assertEqual(seen["snapshot_first"]["comment"], "managed by dstack-ingress")
        self.assertEqual(self.tee(), [])
        self.assertEqual(self.fake.dns, [self.node_record])  # node.* record untouched
        self.assertTrue(self.docs(out)[-1]["ok"])
        code, out, err = self.undo("--confirm", self.token())
        self.assertEqual(code, 0, err)
        self.assertTrue(self.docs(out)[-1]["ok"])
        created = [c for c in self.fake.calls if c[0] == "create_dns_record"][-1][2]
        self.assertEqual(created, {"type": "CNAME", "name": HOST, "content": "y.example.test", "ttl": 300,
                                   "proxied": False, "comment": "managed by dstack-ingress", "tags": ["env:prod"]})
        restored = self.tee()[0]
        self.assertNotEqual(restored["id"], "dns-tee-2")  # documented: re-creation allocates a new id
        original = json.loads(self.original)[1]
        self.assertEqual({k: v for k, v in restored.items() if k != "id"},
                         {k: v for k, v in original.items() if k not in ("id", "modified_on")})
        self.assertEqual(self.fake.dns[0], self.node_record)
        code, _, err = self.undo("--confirm", self.token())  # a finished snapshot can not be replayed
        self.assertEqual(code, 1)
        self.assertIn("already undone", err)

    def test_remove_second_apply_is_refused_without_changes(self):
        h = self.plan(*self.REMOVE)["plan_hash"]
        self.apply(h, *self.REMOVE, "--i-understand-ttl")
        writes = len(self.dns_writes())
        code, _, err = self.run_cli("plan", *self.target(*self.REMOVE))
        self.assertEqual(code, 1)
        self.assertIn("nothing to act on", err)
        self.assertEqual(len(self.dns_writes()), writes)

    def test_remove_drift_when_a_different_record_appears(self):
        h = self.plan(*self.REMOVE)["plan_hash"]
        self.apply(h, *self.REMOVE, "--i-understand-ttl")
        self.fake.dns.append({"id": "dns-other", "type": "CNAME", "name": HOST, "content": "elsewhere.example.test",
                              "proxied": False, "ttl": 60, "comment": None, "tags": []})
        code, out, _ = self.undo("--confirm", self.token())
        self.assertEqual(code, 1)
        self.assertEqual(self.tee()[0]["content"], "elsewhere.example.test")
        code, _, err = self.undo("--confirm", self.token(), "--force-drift")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.tee()[0]["content"], "y.example.test")
        self.assertEqual(self.tee()[0]["id"], "dns-other")  # overwritten in place, no duplicate
        self.assertEqual(len(self.tee()), 1)
        self.assertEqual(json.loads(self.snap.read_text())["forced_undo"][0]["overwrote"]["record"]["ttl"], 60)

    def test_dns_levers_refuse_missing_record_wrong_type_and_ambiguity(self):
        for lever in (self.FLIP, self.REMOVE):
            with self.subTest(lever=lever[1], case="wrong type"):
                code, _, err = self.run_cli("plan", *self.target("--lever", lever[1], "--expect-type", "A"))
                self.assertEqual(code, 1)
                self.assertIn("type is CNAME, expected A", err)
            with self.subTest(lever=lever[1], case="no expected type"):
                code, _, err = self.run_cli("plan", *self.target("--lever", lever[1]))
                self.assertEqual(code, 1)
                self.assertIn("--expect-type", err)
        duplicate = dict(self.fake.dns[1], id="dns-dup", type="A", content="192.0.2.1")
        self.fake.dns.append(duplicate)
        code, _, err = self.run_cli("plan", *self.target(*self.REMOVE))
        self.assertEqual(code, 1)
        self.assertIn("at most one", err)
        self.fake.dns = [r for r in self.fake.dns if r["name"] != HOST]
        for lever in (self.FLIP, self.REMOVE):
            code, _, err = self.run_cli("plan", *self.target(*lever))
            self.assertEqual(code, 1)
            self.assertIn("nothing to act on", err)
        self.assertEqual(self.dns_writes(), [])
        self.assertEqual(self.fake.writes(), [])

    def test_failed_dns_write_leaves_snapshot_and_recovery(self):
        h = self.plan(*self.REMOVE)["plan_hash"]

        def boom(zone, record_id):
            raise sw.CfError(f"delete_dns_record: HTTP 500 {TOKEN}")

        self.fake.delete_dns_record = boom
        code, _, err = self.apply(h, *self.REMOVE, "--i-understand-ttl")
        self.assertEqual(code, 3)
        self.assertIn("APPLY FAILED", err)
        self.assertNotIn(TOKEN, err)
        self.assertEqual(json.loads(self.snap.read_text())["status"], "pending")
        self.assertEqual(json.dumps(self.fake.dns), self.original)
        code, out, _ = self.undo("--confirm", self.token())
        self.assertEqual(code, 0)
        self.assertIn("nothing to undo", self.docs(out)[0]["result"])


class ReviewFixesTest(Base):
    def test_target_host_is_allow_listed_and_node_is_always_protected(self):
        code, _, err = self.run_cli("plan", *self.target("--host", NODE, "--protect-host", "x.example.test"))
        self.assertEqual(code, 1)  # --protect-host is additive: it can not un-protect node.*
        self.assertIn("protected host", err)
        doc = self.plan("--host", "account.tinycloud.xyz", "--allow-inert")
        self.assertIn("NON-STANDARD TARGET", doc["blockers"][0])
        self.assertEqual(doc["protected_hosts"], [NODE])
        h = doc["plan_hash"]
        code, _, err = self.apply(h, "--host", "account.tinycloud.xyz", "--allow-inert")
        self.assertEqual(code, 1)
        self.assertIn("NON-STANDARD TARGET", err)
        self.assertEqual(self.fake.writes(), [])
        self.fake.dns.append({"id": "dns-acc", "type": "CNAME", "name": "account.tinycloud.xyz",
                              "content": "z.example.test", "proxied": True, "ttl": 1})
        doc = self.plan("--host", "account.tinycloud.xyz", "--other-host")
        code, _, err = self.apply(doc["plan_hash"], "--host", "account.tinycloud.xyz", "--other-host")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.fake.rules[0]["expression"], '(http.host eq "account.tinycloud.xyz")')

    def test_extra_protected_hosts_are_guarded_and_listed(self):
        extra = "billing.tinycloud.xyz"
        code, _, err = self.run_cli("plan", *self.target("--host", extra, "--protect-host", extra))
        self.assertEqual(code, 1)
        self.assertEqual(self.plan("--protect-host", extra)["protected_hosts"], sorted([NODE, extra]))

    def test_rule_added_concurrently_survives_apply_and_forced_undo(self):
        h = self.plan()["plan_hash"]
        theirs = {"id": "r-ffff6666", "version": "1", "action": "log", "expression": "(true)",
                  "description": "added during apply", "enabled": True}
        self.fake.before_put = lambda: self.fake.rules.append(copy.deepcopy(theirs))
        code, out, _ = self.apply(h)
        self.assertEqual(code, 4)  # verify reports the rule set changed under us; nothing was lost
        self.assertIn(theirs, self.fake.rules)
        self.assertEqual(self.fake.rules[0]["description"], sw.MARKER)
        self.fake.before_put = None
        code, _, _ = self.undo("--confirm", self.token())
        self.assertEqual(code, 1)  # drift: refused
        code, out, err = self.undo("--confirm", self.token(), "--force-drift")
        self.assertEqual(code, 4, err)  # ours is gone, but verify says the list is not the recorded one
        self.assertFalse(self.docs(out)[-1]["checks"]["restored_to_recorded_prior_state"])
        self.assertIn(theirs, self.fake.rules)  # rule-level delete: only ours was removed
        self.assertEqual([r["description"] for r in self.fake.rules], ["allow monitor", "legacy", "added during apply"])
        writes = [c[0] for c in self.fake.writes()]
        self.assertEqual(writes, ["add_rule", "delete_rule"])  # no whole-list write exists any more

    def test_snapshot_ids_are_revalidated_on_load(self):
        self.applied()
        saved = json.loads(self.snap.read_text())
        for key, bad in (("zone_id", "../../x"), ("host", 'x") or true or ("'), ("protect_hosts", ["x.example.test"])):
            with self.subTest(key=key):
                broken = dict(saved, **{key: bad})
                self.snap.write_text(json.dumps(broken))
                calls = len(self.fake.calls)
                code, _, err = self.run_cli("verify", "--snapshot", str(self.snap))
                self.assertEqual(code, 1)
                self.assertEqual(len(self.fake.calls), calls)  # refused before any API call

    def test_snapshot_file_and_directory_are_fsynced(self):
        with mock.patch.object(sw, "fsync_dir") as fsync_dir:
            self.applied()
        self.assertEqual(fsync_dir.call_count, 2)  # exclusive create + the "applied" replace

    def test_real_client_never_follows_redirects(self):
        import urllib.request
        self.assertIsNone(sw._NoRedirect().redirect_request(None, None, 301, "", {}, "https://elsewhere.test/"))
        opener = sw.CloudflareClient(TOKEN)._opener.__self__
        self.assertTrue(any(isinstance(h, sw._NoRedirect) for h in opener.handlers))
        self.assertFalse(any(type(h) is urllib.request.HTTPRedirectHandler for h in opener.handlers))

    def test_a_host_that_node_cnames_to_is_protected(self):
        self.fake.dns[0]["content"] = HOST.upper() + "."  # node.* -> tee.node (in-zone target)
        code, _, err = self.run_cli("plan", *self.target())
        self.assertEqual(code, 1)
        self.assertIn("CNAME to", err)
        self.assertEqual(self.fake.writes(), [])

    def test_undo_needs_this_snapshots_token_not_the_plan_hash(self):
        h = self.applied()
        code, _, err = self.undo("--confirm", h)
        self.assertEqual(code, 1)
        self.assertIn("undo token", err)
        self.assertEqual([c[0] for c in self.fake.writes()], ["add_rule"])
        code, out, _ = self.undo()  # dry-run prints the token to confirm with
        self.assertEqual(self.docs(out)[0]["undo_token"], self.token())
        self.assertNotEqual(self.token(), h)

    def test_replayed_undo_of_a_finished_snapshot_never_reverts_a_newer_apply(self):
        cases = (("waf", ()),
                 ("security-level", ("--lever", "security-level", "--allow-zone-wide")),
                 ("worker-route", ("--lever", "worker-route", "--allow-no-block")),
                 ("dns-proxy-flip", ("--lever", "dns-proxy-flip", "--expect-type", "CNAME", "--accept-tls-change")),
                 ("dns-remove", ("--lever", "dns-remove", "--expect-type", "CNAME", "--i-understand-ttl")))
        for name, flags in cases:
            with self.subTest(lever=name):
                self.fake = FakeCF()
                if name.startswith("dns-"):
                    self.fake.dns[1].update(proxied=False, ttl=300)
                first, second = self.dir / f"{name}-a.json", self.dir / f"{name}-b.json"
                h1 = self.plan(*flags)["plan_hash"]
                self.assertEqual(self.apply(h1, *flags, snap=first)[0], 0)
                token_a = self.token(first)
                code, _, err = self.run_cli("undo", "--snapshot", str(first), "--confirm", token_a)
                self.assertEqual(code, 0, err)
                h2 = self.plan(*flags)["plan_hash"]
                if name == "waf":
                    self.assertEqual(h1, h2)  # the plan hash alone can not tell the two applies apart
                self.assertEqual(self.apply(h2, *flags, snap=second)[0], 0)
                self.assertNotEqual(self.token(second), token_a)
                state = copy.deepcopy((self.fake.rules, self.fake.level, self.fake.routes, self.fake.dns))
                code, _, err = self.run_cli("undo", "--snapshot", str(first), "--confirm", token_a)  # replay
                self.assertEqual(code, 1)
                self.assertIn("already undone", err)
                self.assertEqual((self.fake.rules, self.fake.level, self.fake.routes, self.fake.dns), state)
                self.assertEqual(json.loads(first.read_text())["status"], "undone")
                self.assertEqual(json.loads(second.read_text())["status"], "applied")

    def test_waf_undo_deletes_only_the_recorded_rule_id(self):
        h = self.applied()
        created = json.loads(self.snap.read_text())["created"]
        self.assertEqual(created, {"rule_id": "r-new0001", "ruleset_id": "rs-7777"})
        self.fake.rules = [r for r in self.fake.rules if r["id"] != created["rule_id"]]  # ours removed by hand
        self.assertEqual(self.plan()["plan_hash"], h)
        self.assertEqual(self.apply(h, snap=self.dir / "b.json")[0], 0)  # a new apply: same marker, new id
        newer = copy.deepcopy(self.fake.rules)
        code, out, _ = self.undo("--confirm", self.token())
        self.assertEqual(code, 1)  # the recorded rule is gone: drift, refused (not merely failed in write)
        self.assertTrue(self.docs(out)[0]["drift"])
        self.assertIn("REFUSED", self.docs(out)[0]["result"])
        code, _, err = self.undo("--confirm", self.token(), "--force-drift")
        self.assertEqual(code, 1)  # even forced, a recorded id that is absent is never replaced by a guess
        self.assertIn("nothing was deleted", err)
        self.assertEqual(self.fake.rules, newer)
        self.assertEqual(json.loads(self.snap.read_text())["status"], "applied")

    def test_waf_force_drift_undo_deletes_the_recorded_rule_not_every_marker_rule(self):
        self.applied()
        copy_of_ours = dict(self.fake.rules[0], id="r-copy0002")  # another rule carrying our marker
        self.fake.rules.append(copy_of_ours)
        code, out, _ = self.undo("--confirm", self.token(), "--force-drift")
        self.assertEqual(code, 4)  # list differs from the recorded prior state: expected after a forced undo
        self.assertIn(copy_of_ours, self.fake.rules)  # not ours: it stays
        self.assertEqual([c[3] for c in self.fake.calls if c[0] == "delete_rule"], ["r-new0001"])

    def test_unpinnable_rule_id_fails_apply_and_undo_refuses_to_guess(self):
        h = self.plan()["plan_hash"]
        stray = {"id": "r-9999aaaa", "action": "log", "expression": "(true)", "description": sw.MARKER,
                 "enabled": True}
        self.fake.before_put = lambda: self.fake.rules.append(copy.deepcopy(stray))  # a second marker rule
        code, _, err = self.apply(h)
        self.assertEqual(code, 3)  # the POST was sent: the zone may have changed, so not a "refused" exit 1
        self.assertIn("could not be pinned", err)
        self.assertIn("APPLY FAILED", err)
        saved = json.loads(self.snap.read_text())
        self.assertEqual((saved["status"], saved["created"]), ("pending", None))
        self.fake.before_put = None
        rules = copy.deepcopy(self.fake.rules)
        for extra in ((), ("--force-drift",)):
            code, _, _ = self.undo("--confirm", self.token(), *extra)
            self.assertEqual(code, 1)  # drift refused / forced but ambiguous: refuses to guess
            self.assertEqual(self.fake.rules, rules)

    def test_lost_post_reply_still_pins_the_created_rule_for_undo(self):
        class LostReply(FakeCF):
            def add_rule(self, *args):
                super().add_rule(*args)
                raise sw.CfError("add_rule: timed out waiting for the reply")  # the rule was created

        self.fake = LostReply()
        original = copy.deepcopy(self.fake.rules)
        code, _, err = self.apply(self.plan()["plan_hash"])
        self.assertEqual(code, 3)
        saved = json.loads(self.snap.read_text())
        self.assertEqual((saved["status"], saved["created"]["rule_id"]), ("pending", "r-new0001"))
        self.assertNotIn(saved["undo_token"], err)  # a pending snapshot's confirm value comes from the undo dry-run
        dry = self.undo_dry_run()
        self.assertEqual(dry["live_state"]["rules"][0]["id"], "…0001")
        code, _, err = self.undo("--confirm", dry["undo_confirm"])
        self.assertEqual(code, 0, err)
        self.assertEqual(self.fake.rules, original)

    def test_snapshot_targets_ids_and_params_are_revalidated_on_load(self):
        self.applied()
        waf = json.loads(self.snap.read_text())
        route_snap = self.dir / "route.json"
        flags = ("--lever", "worker-route", "--allow-no-block")
        self.assertEqual(self.apply(self.plan(*flags)["plan_hash"], *flags, snap=route_snap)[0], 0)
        route = json.loads(route_snap.read_text())
        bad_route = dict(route, before=dict(route["before"], id="../../accounts/x"))
        cases = ((self.snap, dict(waf, host=NODE)),
                 (self.snap, dict(waf, params={"action": "allow"})),
                 (self.snap, dict(waf, created={"rule_id": "../x", "ruleset_id": "rs-7777"})),
                 (self.snap, dict(waf, status="exploded")),
                 (self.snap, dict(waf, undo_token="x")),
                 (self.snap, dict(waf, undo_token="0" * 64)),  # well-formed, but not digest(plan_hash, nonce)
                 (self.snap, dict(waf, nonce="someone-edited-this")),
                 (route_snap, bad_route))
        for path, broken in cases:
            with self.subTest(broken=sorted(k for k in broken if broken[k] != (waf if path == self.snap else route)[k])):
                path.write_text(json.dumps(broken))
                calls = len(self.fake.calls)
                for command in (("verify",), ("undo", "--confirm", "x")):
                    code, _, _ = self.run_cli(command[0], "--snapshot", str(path), *command[1:])
                    self.assertEqual(code, 1)
                self.assertEqual(len(self.fake.calls), calls)  # refused before any API call

    def test_pending_undo_binds_its_confirm_to_the_live_state_waf(self):
        class LostReply(FakeCF):
            def add_rule(self, *args):
                super().add_rule(*args)
                raise sw.CfError("add_rule: reply lost")

        self.fake = LostReply()
        self.assertEqual(self.apply(self.plan()["plan_hash"])[0], 3)
        dry = self.undo_dry_run()
        self.assertEqual([r["description"] for r in dry["live_state"]["rules"]], [sw.MARKER, "allow monitor", "legacy"])
        self.assertEqual([r["description"] for r in dry["recorded_before_state"]["rules"]], ["allow monitor", "legacy"])
        self.assertNotIn("undo_token", dry)
        self.assertNotIn("r-new0001", json.dumps(dry))  # ids are …last4 on stdout
        self.fake.rules[1]["version"] = "99"  # live state moves after the dry-run (still "our" state)
        before_calls = len(self.fake.writes())
        code, _, err = self.undo("--confirm", dry["undo_confirm"])
        self.assertEqual(code, 1)
        self.assertIn("live state", err)
        self.assertEqual(len(self.fake.writes()), before_calls)
        self.assertEqual(json.loads(self.snap.read_text())["status"], "pending")
        fresh = self.undo_dry_run()
        self.assertNotEqual(fresh["undo_confirm"], dry["undo_confirm"])
        code, _, err = self.undo("--confirm", fresh["undo_confirm"])
        self.assertEqual(code, 0, err)
        self.assertEqual([r["id"] for r in self.fake.rules], ["r-aaaa1111", "r-bbbb2222"])

    def test_pending_undo_binds_its_confirm_to_the_live_state_flip(self):
        class LostReply(FakeCF):
            armed = True

            def update_dns_record(self, *args):
                super().update_dns_record(*args)
                if self.armed:
                    raise sw.CfError("update_dns_record: reply lost")

        self.fake = LostReply()
        self.fake.dns[1].update(proxied=False, ttl=300)
        flags = ("--lever", "dns-proxy-flip", "--expect-type", "CNAME", "--accept-tls-change")
        self.assertEqual(self.apply(self.plan(*flags)["plan_hash"], *flags)[0], 3)
        self.fake.armed = False  # only the apply loses its reply
        dry = self.undo_dry_run(None, "--force-drift")
        self.assertEqual((dry["live_state"]["record"]["proxied"], dry["recorded_before_state"]["record"]["proxied"]),
                         (True, False))
        self.assertEqual(self.undo("--confirm", self.token(), "--force-drift")[0], 1)  # the token alone is not enough
        self.fake.dns[1]["content"] = "rewritten.example.test"  # e.g. dstack-ingress, after the dry-run
        updates = len([c for c in self.fake.calls if c[0] == "update_dns_record"])
        code, _, err = self.undo("--confirm", dry["undo_confirm"], "--force-drift")
        self.assertEqual(code, 1)
        self.assertIn("live state", err)
        self.assertEqual(len([c for c in self.fake.calls if c[0] == "update_dns_record"]), updates)
        code, _, err = self.undo("--confirm", self.undo_dry_run(None, "--force-drift")["undo_confirm"],
                                 "--force-drift")
        self.assertEqual(code, 0, err)
        self.assertEqual((self.fake.dns[1]["proxied"], self.fake.dns[1]["ttl"]), (False, 300))
        self.assertEqual(self.fake.dns[1]["content"], "rewritten.example.test")  # never written back

    def test_pending_undo_security_level_shows_live_next_to_recorded(self):
        class LostReply(FakeCF):
            armed = True

            def set_security_level(self, zone, value):
                super().set_security_level(zone, value)
                if self.armed:
                    raise sw.CfError("set_security_level: reply lost")

        self.fake = LostReply()
        flags = ("--lever", "security-level", "--allow-zone-wide")
        self.assertEqual(self.apply(self.plan(*flags)["plan_hash"], *flags)[0], 3)
        self.fake.armed = False  # only the apply loses its reply
        refused = self.run_cli("undo", "--snapshot", str(self.snap))  # pending needs --force-drift
        self.assertEqual(refused[0], 1)
        self.assertEqual(self.docs(refused[1])[0]["live_state"], {"value": "under_attack"})
        dry = self.undo_dry_run(None, "--force-drift")
        self.assertEqual((dry["live_state"], dry["recorded_before_state"]),
                         ({"value": "under_attack"}, {"value": "medium"}))
        self.assertEqual(self.undo("--confirm", self.token(), "--force-drift")[0], 1)
        self.assertEqual(self.fake.level, "under_attack")
        code, _, err = self.undo("--confirm", dry["undo_confirm"], "--force-drift")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.fake.level, "medium")

    def test_pending_undo_of_a_failed_apply_never_reverts_a_later_successful_apply(self):
        class FailsOnce(FakeCF):
            armed = True

            def set_security_level(self, zone, value):
                if self.armed:
                    self.armed = False
                    raise sw.CfError("set_security_level: HTTP 500")  # nothing was changed
                super().set_security_level(zone, value)

        self.fake = FailsOnce()
        flags = ("--lever", "security-level", "--allow-zone-wide")
        first, second = self.dir / "a.json", self.dir / "b.json"
        h = self.plan(*flags)["plan_hash"]
        self.assertEqual(self.apply(h, *flags, snap=first)[0], 3)  # A fails, snapshot A stays pending
        self.assertEqual(self.apply(h, *flags, snap=second)[0], 0)  # the operator retries: B succeeds
        self.assertEqual(self.fake.level, "under_attack")
        code, out, _ = self.run_cli("undo", "--snapshot", str(first))
        self.assertEqual(code, 1)  # A's pending undo is refused without --force-drift
        shown = self.docs(out)[0]
        self.assertIn("REFUSED", shown["result"])
        self.assertEqual((shown["live_state"], shown["recorded_before_state"]),
                         ({"value": "under_attack"}, {"value": "medium"}))  # the live state is B's
        code, _, _ = self.run_cli("undo", "--snapshot", str(first), "--confirm", self.token(first))
        self.assertEqual(code, 1)
        self.assertEqual(self.fake.level, "under_attack")
        code, out, _ = self.run_cli("undo", "--snapshot", str(first), "--force-drift")  # forced dry-run
        self.assertEqual(code, 0)
        self.assertEqual(self.docs(out)[0]["live_state"], {"value": "under_attack"})
        self.assertEqual(self.fake.level, "under_attack")  # nothing executed without the confirm value
        self.assertEqual(json.loads(second.read_text())["status"], "applied")


class TokenAndClientTest(Base):
    def test_token_file_must_be_private_regular_file(self):
        token_file = self.dir / "token"
        token_file.write_text(TOKEN + "\n")
        token_file.chmod(0o640)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = sw.main(["plan", "--token-file", str(token_file), *self.target()],
                           client_factory=lambda t: self.fail("client must not be built"))
        self.assertEqual(code, 1)
        token_file.chmod(0o600)
        link = self.dir / "link"
        link.symlink_to(token_file)
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = sw.main(["plan", "--token-file", str(link), *self.target()],
                           client_factory=lambda t: self.fail("client must not be built"))
        self.assertEqual(code, 1)
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = sw.main(["plan", "--token-file", str(token_file), *self.target()],
                           client_factory=lambda t: self.fake)
        self.assertEqual(code, 0)
        self.assertNotIn(TOKEN, out.getvalue() + err.getvalue())

    def test_missing_env_token_is_refused_without_client(self):
        with mock.patch.dict(os.environ, {ENV: ""}):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = sw.main(["plan", "--token-env", ENV, *self.target()],
                               client_factory=lambda t: self.fail("client must not be built"))
        self.assertEqual(code, 1)

    def test_real_client_requests_with_stub_opener_and_redacted_errors(self):
        sent = []

        class Response(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def opener(request, timeout=None):
            sent.append((request.method, request.full_url, request.data, request.get_header("Authorization")))
            if request.full_url.endswith("/entrypoint") and request.method == "GET":
                raise HTTPError(request.full_url, 404, "nf", {}, io.BytesIO(TOKEN.encode()))
            if request.full_url.endswith("/security_level") and request.method == "PATCH":
                raise HTTPError(request.full_url, 403, "no", {}, io.BytesIO(TOKEN.encode()))
            return Response(json.dumps({"success": True, "result": {"value": "medium"}}).encode())

        client = sw.CloudflareClient(TOKEN, opener=opener)
        self.assertEqual(client.security_level(ZONE), "medium")
        self.assertEqual(sent[0][:2], ("GET", f"{sw.API}/zones/{ZONE}/settings/security_level"))
        self.assertEqual(sent[0][3], "Bearer " + TOKEN)
        self.assertIsNone(client.entrypoint(ZONE))  # 404 = no entrypoint ruleset yet
        with self.assertRaises(sw.CfError) as raised:
            client.set_security_level(ZONE, "under_attack")
        self.assertNotIn(TOKEN, str(raised.exception))
        self.assertEqual(sent[-1][2], b'{"value": "under_attack"}')
        client.create_entrypoint(ZONE, [{"a": 1}])
        self.assertEqual((sent[-1][0], sent[-1][2]), ("PUT", b'{"rules": [{"a": 1}]}'))
        client.add_rule(ZONE, "rs-1", {"action": "block"}, 1)
        self.assertEqual((sent[-1][0], sent[-1][1]), ("POST", f"{sw.API}/zones/{ZONE}/rulesets/rs-1/rules"))
        self.assertEqual(json.loads(sent[-1][2]), {"action": "block", "position": {"index": 1}})
        client.delete_rule(ZONE, "rs-1", "rule-9")
        self.assertEqual((sent[-1][0], sent[-1][1], sent[-1][2]),
                         ("DELETE", f"{sw.API}/zones/{ZONE}/rulesets/rs-1/rules/rule-9", None))
        body = {"type": "CNAME", "name": HOST, "content": "y.example.test", "ttl": 300, "proxied": False,
                "comment": None, "tags": []}
        client.update_dns_record(ZONE, "dns-tee-2", body)
        self.assertEqual((sent[-1][0], sent[-1][1]), ("PATCH", f"{sw.API}/zones/{ZONE}/dns_records/dns-tee-2"))
        self.assertEqual(json.loads(sent[-1][2]), body)
        client.create_dns_record(ZONE, body)
        self.assertEqual((sent[-1][0], sent[-1][1]), ("POST", f"{sw.API}/zones/{ZONE}/dns_records"))
        client.delete_dns_record(ZONE, "dns-tee-2")
        self.assertEqual((sent[-1][0], sent[-1][1], sent[-1][2]),
                         ("DELETE", f"{sw.API}/zones/{ZONE}/dns_records/dns-tee-2", None))


if __name__ == "__main__":
    unittest.main()
