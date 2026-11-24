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
MUTATORS = {"put_entrypoint_rules", "set_security_level", "set_route_script"}


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
        self.before_put = None  # hook run at the start of a put
        self.fail_put = False
        self._n = 0

    def writes(self):
        return [c for c in self.calls if c[0] in MUTATORS]

    def security_level(self, zone):
        self.calls.append(("security_level", zone))
        return self.level

    def set_security_level(self, zone, value):
        self.calls.append(("set_security_level", zone, value))
        self.level = value

    def entrypoint_rules(self, zone):
        self.calls.append(("entrypoint_rules", zone))
        return copy.deepcopy(self.rules)

    def put_entrypoint_rules(self, zone, rules):
        self.calls.append(("put_entrypoint_rules", zone, copy.deepcopy(rules)))
        if self.before_put:
            self.before_put()
        if self.fail_put:
            raise sw.CfError(f"put_entrypoint_rules: HTTP 500 Authorization: Bearer {TOKEN}")
        stored = copy.deepcopy(rules)
        for rule in stored:
            if "id" not in rule:
                self._n += 1
                rule.update(id=f"r-new{self._n:04d}", version="1", last_updated="2026-11-24T00:00:00Z")
        self.rules = stored

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
        self.assertEqual(doc["change"]["insert_rule_at_position"], 1)
        self.assertEqual(doc["undo"]["restored_rules"]["count"], 2)
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
        code, out, err = self.undo("--confirm", h)
        self.assertEqual(code, 0, err)
        self.assertEqual(json.dumps(self.fake.rules), original)
        self.assertEqual(self.fake.calls[-1][0], "dns_records")
        puts = [c for c in self.fake.calls if c[0] == "put_entrypoint_rules"]
        self.assertEqual(json.dumps(puts[-1][2]), original)  # the exact recorded list was sent
        self.assertTrue(self.docs(out)[-1]["ok"])
        self.assertEqual(json.loads(self.snap.read_text())["status"], "undone")
        code, out, _ = self.undo("--confirm", h)  # already restored
        self.assertEqual(code, 0)
        self.assertIn("nothing to undo", self.docs(out)[0]["result"])

    def test_undo_restores_absent_entrypoint_as_empty_rules(self):
        self.fake.rules = None  # entrypoint ruleset does not exist yet
        h = self.applied()
        self.assertEqual(len(self.fake.rules), 1)
        code, _, err = self.undo("--confirm", h)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.fake.rules, [])

    def test_drift_is_refused_then_forced_with_record(self):
        h = self.applied()
        added = {"id": "r-dddd4444", "version": "1", "action": "log", "expression": "(true)",
                 "description": "added by someone else", "enabled": True}
        self.fake.rules.append(added)
        snapshot_before = self.snap.read_bytes()
        code, out, _ = self.undo("--confirm", h)
        self.assertEqual(code, 1)
        self.assertIn("REFUSED", self.docs(out)[0]["result"])
        self.assertIn(added, self.fake.rules)
        self.assertEqual(self.snap.read_bytes(), snapshot_before)
        code, out, err = self.undo("--confirm", h, "--force-drift")
        self.assertEqual(code, 0, err)
        self.assertNotIn(added, self.fake.rules)
        forced = json.loads(self.snap.read_text())["forced_undo"]
        self.assertEqual(len(forced), 1)
        self.assertIn(added, forced[0]["overwrote"]["rules"])

    def test_edited_lever_rule_counts_as_drift(self):
        h = self.applied()
        self.fake.rules[0]["action"] = "log"
        code, _, _ = self.undo("--confirm", h)
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
        code, out, _ = self.undo("--confirm", h)
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
        self.undo("--confirm", h)
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
        self.assertEqual(self.fake.writes()[0][0], "put_entrypoint_rules")
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
        code, _, err = self.undo("--confirm", doc["plan_hash"])
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
        code, _, err = self.undo("--confirm", doc["plan_hash"])
        self.assertEqual(code, 0, err)
        self.assertEqual(json.dumps(self.fake.routes), json.dumps(before))


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
        self.assertIsNone(client.entrypoint_rules(ZONE))  # 404 = no entrypoint ruleset yet
        with self.assertRaises(sw.CfError) as raised:
            client.set_security_level(ZONE, "under_attack")
        self.assertNotIn(TOKEN, str(raised.exception))
        self.assertEqual(sent[-1][2], b'{"value": "under_attack"}')
        client.put_entrypoint_rules(ZONE, [{"a": 1}])
        self.assertEqual((sent[-1][0], sent[-1][2]), ("PUT", b'{"rules": [{"a": 1}]}'))


if __name__ == "__main__":
    unittest.main()
