#!/usr/bin/env python3
"""Fakes-only contracts for ingress-cf-only.py: no network, no Cloudflare, no Phala.

The real ingress-switch.py runs as a local subprocess on temporary files; every
Cloudflare/HTTP/TCP interaction is a fake client defined here.
"""
import contextlib
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from urllib.error import HTTPError, URLError

SCRIPT = Path(__file__).with_name("ingress-cf-only.py")
spec = importlib.util.spec_from_file_location("ingress_cf_only", SCRIPT)
cf_only = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cf_only)

APP = "a" * 40
INSTANCE = "b" * 40
TUNNEL = "11111111-2222-4333-8444-555555555555"
HOST = "cf-origin.example.test"
GATEWAY = "gw.example.test"
MGMT = f"{APP}-10022.{GATEWAY}"
NODE = "did:key:z6MkCanaryNodeId"
CF_TOKEN = "cf-token-canary-0123"
SECRET = "secret-marker"


def good_cf():
    return {
        "tunnel": {"id": TUNNEL, "status": "healthy", "deleted_at": None,
                   "connections": [{"id": "c1", "is_pending_reconnect": False}]},
        "ingress": [{"hostname": HOST, "service": "http://tinycloud:8000"}, {"service": "http_status:404"}],
        "dns": [{"type": "CNAME", "proxied": True, "content": f"{TUNNEL}.cfargotunnel.com"}],
        "worker": {"version_id": "ver-1", "origin_binding": "secret_text",
                   "routes": [{"pattern": "node.tinycloud.xyz/*", "script": "tinycloud-tee-proxy"},
                              {"pattern": "tee.node.tinycloud.xyz/*", "script": "tinycloud-tee-proxy"}]},
    }


class FakeCf:
    def __init__(self, state=None):
        self.state = state or good_cf()
        self.calls = []

    def tunnel(self, tunnel_id):
        self.calls.append("tunnel")
        return self.state["tunnel"]

    def tunnel_ingress(self, tunnel_id):
        self.calls.append("ingress")
        return self.state["ingress"]

    def dns_records(self, name):
        self.calls.append("dns")
        return self.state["dns"]

    def worker(self, script):
        self.calls.append("worker")
        return self.state["worker"]


class FakeHttp:
    """Models a restricted gateway by default; override per host to model failures."""

    def __init__(self, restricted=True):
        self.info_map = {HOST: {"status": 200, "node_id": NODE}, "node.tinycloud.xyz": {"status": 200, "node_id": NODE}}
        self.probe_map = {}
        self.restricted = restricted
        self.mgmt = "open"
        self.probes = []

    def info(self, host):
        return self.info_map.get(host, {"status": None, "node_id": None})

    def probe(self, host, family, port=443):
        self.probes.append((host, family, port))
        if (host, family) in self.probe_map:
            return self.probe_map[(host, family)]
        return {"outcome": "refused"} if self.restricted else {"outcome": "node_info", "node_id": NODE}

    def tcp_probe(self, host, port, family):
        assert (host, port, family) == (MGMT, 10022, "ipv4")
        return self.mgmt


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.compose = self.root / "app-compose.json"
        self.target = self.root / "target.json"
        self.network = self.root / "network.json"
        self.snapshot = self.root / "previous.json"
        self.receipt = self.root / "receipt.json"
        self.patch = self.root / "restrict.patch.json"
        self.original = {"gateway_enabled": True, "docker_compose_file": f"unchanged: {SECRET}",
                         "port_policy": None}
        self.save(self.compose, self.original)
        self.save(self.target, {"id": "cvm_local", "app_id": APP})
        self.save(self.network, {"cvm_id": "cvm_local", "is_online": True, "error": None,
                                 "ingress": {"gateway_enabled": True, "port_policy": None}, "port_mappings": []})
        self.cf, self.http = FakeCf(), FakeHttp()

    def save(self, path, value):
        path.write_text(json.dumps(value))
        path.chmod(0o600)

    def clients(self):
        return cf_only.Clients(self.http, self.cf)

    def cloudflare_args(self):
        return ["--expect-app-id", APP, "--tunnel-id", TUNNEL, "--tunnel-host", HOST,
                "--account-id", "acct", "--zone-id", "zone", "--attest-origin-is-tunnel-host"]

    def switch_args(self):
        return ["--compose", str(self.compose), "--target", str(self.target), "--network", str(self.network),
                "--snapshot", str(self.snapshot)]

    def verify_args(self, *extra, expect="restricted"):
        return ["--expect", expect, "--expect-app-id", APP, "--instance-id", INSTANCE, "--gateway-domain", GATEWAY,
                "--management-endpoint", f"{MGMT}:10022", "--tunnel-host", HOST, "--snapshot", str(self.snapshot),
                "--receipt", str(self.receipt), *extra]

    def run_cli(self, argv, now=None):
        out, err = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = cf_only.main(argv, clients=self.clients(), now=now, out=out)
        except cf_only.Refusal as error:
            return 1, out.getvalue(), str(error)
        return code, out.getvalue(), err.getvalue()

    def plan(self):
        code, out, err = self.run_cli(["plan", *self.cloudflare_args(), *self.switch_args()])
        self.assertEqual(code, 0, err)
        return json.loads(out)

    def stage(self):
        digest = self.plan()["plan_hash"]
        code, out, err = self.run_cli(["apply-patch", *self.cloudflare_args(), *self.switch_args(),
                                       "--confirm", digest, "--patch-out", str(self.patch)])
        self.assertEqual(code, 0, err)
        return json.loads(out)


class PreflightTest(Base):
    def test_receipt_is_built_from_reads_and_privately_written(self):
        code, out, err = self.run_cli(["preflight", *self.cloudflare_args(), "--out", str(self.receipt)])
        self.assertEqual(code, 0, err)
        saved = json.loads(self.receipt.read_text())
        self.assertEqual(self.receipt.stat().st_mode & 0o777, 0o600)
        self.assertEqual((saved["tunnel_id"], saved["worker_origin"], saved["tunnel_hostname"], saved["app_id"]),
                         (TUNNEL, f"https://{HOST}", HOST, APP))
        self.assertEqual((saved["origin_node_id"], saved["public_node_id"], saved["worker_version_id"]),
                         (NODE, NODE, "ver-1"))
        self.assertIs(saved["connector_authenticated"], True)
        self.assertEqual((saved["origin_status"], saved["public_status"]), (200, 200))
        self.assertIn("not a cryptographic attestation", saved["evidence_label"])
        self.assertIn("not a cryptographic attestation", out)
        self.assertEqual(sorted(self.cf.calls), ["dns", "ingress", "tunnel", "worker"])

    def test_refuses_on_each_mismatch_or_missing_evidence(self):
        def mutate(fn):
            def apply(cf, http):
                fn(cf.state, http)
            return apply

        cases = {
            "other tunnel": lambda s, h: s["tunnel"].update(id="99999999-2222-4333-8444-555555555555"),
            "deleted tunnel": lambda s, h: s["tunnel"].update(deleted_at="2026-01-01T00:00:00Z"),
            "degraded": lambda s, h: s["tunnel"].update(status="degraded"),
            "no connections": lambda s, h: s["tunnel"].update(connections=[]),
            "pending reconnect": lambda s, h: s["tunnel"]["connections"][0].update(is_pending_reconnect=True),
            "ingress wrong service": lambda s, h: s["ingress"][0].update(service="http://elsewhere:80"),
            "ingress missing host": lambda s, h: s["ingress"][0].update(hostname="other.example.test"),
            "dns missing": lambda s, h: s.update(dns=[]),
            "dns other tunnel": lambda s, h: s["dns"][0].update(content="x.cfargotunnel.com"),
            "dns not proxied": lambda s, h: s["dns"][0].update(proxied=False),
            "dns duplicated": lambda s, h: s["dns"].append(dict(s["dns"][0])),
            "worker origin is a plain_text var": lambda s, h: s["worker"].update(origin_binding="plain_text"),
            "worker origin binding absent": lambda s, h: s["worker"].update(origin_binding=None),
            "worker version unreadable": lambda s, h: s["worker"].update(version_id=None),
            "node route missing": lambda s, h: s["worker"].update(routes=[]),
            "node route other script": lambda s, h: s["worker"]["routes"][0].update(script="other"),
            "origin info unhealthy": lambda s, h: h.info_map[HOST].update(status=503),
            "public info unreachable": lambda s, h: h.info_map.pop("node.tinycloud.xyz"),
            "node ids differ": lambda s, h: h.info_map[HOST].update(node_id="did:key:other"),
            "node id missing": lambda s, h: [h.info_map[k].update(node_id=None) for k in list(h.info_map)],
        }
        for name, fn in cases.items():
            with self.subTest(name):
                self.cf, self.http = FakeCf(), FakeHttp()
                fn(self.cf.state, self.http)
                code, out, err = self.run_cli(["preflight", *self.cloudflare_args(), "--out", str(self.receipt)])
                self.assertEqual(code, 1, out)
                self.assertFalse(self.receipt.exists())

    def test_refuses_wrong_worker_version_bad_tunnel_id_and_non_independent_host(self):
        base = self.cloudflare_args()
        for name, argv in {
            "version": [*base, "--expect-worker-version", "ver-0"],
            "tunnel id": [a if a != TUNNEL else "not-a-uuid" for a in base],
            "phala host": [a if a != HOST else f"{APP}-8000.dstack.phala.network" for a in base],
            "public host": [a if a != HOST else "node.tinycloud.xyz" for a in base],
        }.items():
            with self.subTest(name):
                code, out, err = self.run_cli(["preflight", *argv])
                self.assertEqual(code, 1, out)


class PlanApplyTest(Base):
    def test_plan_prints_change_undo_hash_and_writes_nothing(self):
        before = self.compose.read_bytes()
        plan = self.plan()
        self.assertEqual(plan["intended_change"]["patch"], {"compose": {"port_policy": {
            "restrict_mode": True, "ports": [{"port": 10022, "pp": False}]}}})
        self.assertEqual(plan["exact_undo"]["patch"], {"compose": {"port_policy": None}})
        self.assertRegex(plan["plan_hash"], r"^[0-9a-f]{64}$")
        self.assertIn("restarts the CVM", plan["warning"])
        self.assertEqual(self.compose.read_bytes(), before)
        self.assertFalse(self.snapshot.exists())

    def test_plan_hash_is_stable_but_tracks_every_input(self):
        base = self.plan()["plan_hash"]
        self.assertEqual(self.plan()["plan_hash"], base)
        self.http.info_map[HOST]["node_id"] = self.http.info_map["node.tinycloud.xyz"]["node_id"] = "did:key:z6MkOther"
        self.assertNotEqual(self.plan()["plan_hash"], base)
        self.http.info_map[HOST]["node_id"] = self.http.info_map["node.tinycloud.xyz"]["node_id"] = NODE
        self.cf.state["worker"]["version_id"] = "ver-2"
        self.assertNotEqual(self.plan()["plan_hash"], base)
        self.cf.state["worker"]["version_id"] = "ver-1"
        self.save(self.compose, dict(self.original, unrelated=1))
        self.assertNotEqual(self.plan()["plan_hash"], base)

    def test_apply_patch_requires_matching_confirm_and_never_calls_phala(self):
        digest = self.plan()["plan_hash"]
        args = ["apply-patch", *self.cloudflare_args(), *self.switch_args(), "--patch-out", str(self.patch)]
        for confirm in ("0" * 64, digest[:-1], ""):
            with self.subTest(confirm=confirm):
                code, out, err = self.run_cli([*args, "--confirm", confirm])
                self.assertEqual(code, 1)
                self.assertFalse(self.snapshot.exists() or self.patch.exists())
                self.assertEqual(json.loads(self.compose.read_text()), self.original)
        spawned = []
        real_run = subprocess.run

        def record(argv, **kwargs):
            spawned.append(argv)
            return real_run(argv, **kwargs)

        with mock.patch.object(cf_only.subprocess, "run", record):
            code, out, err = self.run_cli([*args, "--confirm", digest])
        self.assertEqual(code, 0, err)
        self.assertTrue(spawned and all(Path(a[1]).name == "ingress-switch.py" for a in spawned))
        result = json.loads(out)
        self.assertEqual(result["phala_command_for_authorized_operator"],
                         f"phala api /cvms/cvm_local -X PATCH --input {self.patch}")
        self.assertIn("NO Phala call", result["executed_by_this_script"])
        self.assertEqual(json.loads(self.patch.read_text()), result["payload"])
        self.assertEqual(result["payload"]["compose"]["port_policy"]["restrict_mode"], True)
        self.assertEqual(self.snapshot.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.patch.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(self.compose.read_text())["port_policy"]["restrict_mode"], True)

    def test_confirm_goes_stale_when_evidence_changes_between_plan_and_apply(self):
        digest = self.plan()["plan_hash"]
        self.http.info_map[HOST]["node_id"] = self.http.info_map["node.tinycloud.xyz"]["node_id"] = "did:key:z6MkOther"
        code, out, err = self.run_cli(["apply-patch", *self.cloudflare_args(), *self.switch_args(),
                                       "--confirm", digest, "--patch-out", str(self.patch)])
        self.assertEqual(code, 1)
        self.assertFalse(self.snapshot.exists() or self.patch.exists())

    def test_plan_and_apply_refuse_when_preflight_refuses(self):
        self.cf.state["tunnel"]["status"] = "down"
        code, out, err = self.run_cli(["plan", *self.cloudflare_args(), *self.switch_args()])
        self.assertEqual(code, 1)
        self.assertEqual(out, "")


class VerifyTest(Base):
    def setUp(self):
        super().setUp()
        code, out, err = self.run_cli(["preflight", *self.cloudflare_args(), "--out", str(self.receipt)])
        self.assertEqual(code, 0, err)
        self.stage()

    def verify(self, *extra, expect="restricted", now=None):
        return self.run_cli(["verify", *self.verify_args(*extra, expect=expect)], now=now)

    def failed(self, out):
        return [c["check"] for c in json.loads(out)["checks"] if not c["ok"]]

    def test_passes_when_every_condition_holds_over_ipv4_and_ipv6(self):
        code, out, err = self.verify()
        self.assertEqual(code, 0, out)
        result = json.loads(out)
        self.assertEqual(result["result"], "pass")
        probed = {(h, f) for h, f, p in self.http.probes}
        for host in (cf_only.TEE_HOST, f"{APP}-443s.{GATEWAY}", f"{INSTANCE}-443s.{GATEWAY}",
                     f"{APP}-8000.{GATEWAY}", f"{INSTANCE}-443.{GATEWAY}"):
            for family in ("ipv4", "ipv6"):
                self.assertIn((host, family), probed)
        self.assertTrue(result["not_covered"])

    def test_fails_on_each_condition(self):
        cases = {
            "tee ipv4 still serves": (lambda h: h.probe_map.update({(cf_only.TEE_HOST, "ipv4"):
                                      {"outcome": "node_info", "node_id": NODE}}), "tee.node.tinycloud.xyz fresh ipv4"),
            "instance -443s ipv6 still serves": (lambda h: h.probe_map.update({(f"{INSTANCE}-443s.{GATEWAY}", "ipv6"):
                                                 {"outcome": "node_info", "node_id": NODE}}), "-443s.gw.example.test fresh ipv6"),
            "app timeout is not refusal": (lambda h: h.probe_map.update({(f"{APP}-8000.{GATEWAY}", "ipv4"):
                                           {"outcome": "timeout"}}), f"{APP}-8000"),
            "ipv4 resolver error is not refusal": (lambda h: h.probe_map.update({(f"{APP}-443.{GATEWAY}", "ipv4"):
                                                   {"outcome": "no_address"}}), f"{APP}-443."),
            "ipv6 without AAAA is unverified": (lambda h: h.probe_map.update({(cf_only.TEE_HOST, "ipv6"):
                                                {"outcome": "no_address"}}), "tee.node.tinycloud.xyz fresh ipv6"),
            "node.* unhealthy": (lambda h: h.info_map["node.tinycloud.xyz"].update(status=502), "node.tinycloud.xyz /info"),
            "node ids differ": (lambda h: h.info_map[HOST].update(node_id="did:key:z6MkOther"), "tunnel host /info"),
            "management closed": (lambda h: setattr(h, "mgmt", "refused"), "management port 10022"),
        }
        for name, (fn, expected) in cases.items():
            with self.subTest(name):
                self.http = FakeHttp()
                fn(self.http)
                code, out, err = self.verify()
                self.assertEqual(code, 1, out)
                self.assertTrue(any(expected in c for c in self.failed(out)), self.failed(out))

    def test_ipv6_without_aaaa_only_passes_when_explicitly_accepted(self):
        self.http.probe_map = {(h, "ipv6"): {"outcome": "no_address"} for h in cf_only.direct_hosts(
            mock.Mock(expect_app_id=APP, instance_id=INSTANCE, gateway_domain=GATEWAY, extra_host=None))}
        self.assertEqual(self.verify()[0], 1)
        code, out, err = self.verify("--allow-no-aaaa")
        self.assertEqual(code, 0, out)
        self.assertIn("not proof of no IPv6 path", out)

    def test_refuses_stale_receipt_loose_snapshot_and_other_app(self):
        self.assertEqual(self.verify(now=datetime.now(timezone.utc) + timedelta(hours=2))[0], 1)
        self.snapshot.chmod(0o644)
        self.assertEqual(self.verify()[0], 1)
        self.snapshot.chmod(0o600)
        snap = json.loads(self.snapshot.read_text())
        self.save(self.snapshot, dict(snap, app_id="c" * 40))
        self.assertEqual(self.verify()[0], 1)

    def test_management_is_expected_closed_when_the_policy_denies_it(self):
        snap = json.loads(self.snapshot.read_text())
        self.save(self.snapshot, dict(snap, after={"restrict_mode": True, "ports": []}))
        self.http.mgmt = "refused"
        self.assertEqual(self.verify()[0], 0)
        self.http.mgmt = "open"
        self.assertEqual(self.verify()[0], 1)

    def test_restored_expectation_needs_tee_to_serve_the_same_node(self):
        self.http = FakeHttp(restricted=False)
        code, out, err = self.verify(expect="restored")
        self.assertEqual(code, 0, out)
        self.http.probe_map[(cf_only.TEE_HOST, "ipv4")] = {"outcome": "node_info", "node_id": "did:key:z6MkOther"}
        self.assertEqual(self.verify(expect="restored")[0], 1)
        self.http.probe_map[(cf_only.TEE_HOST, "ipv4")] = {"outcome": "refused"}
        self.assertEqual(self.verify(expect="restored")[0], 1)


class UndoTest(Base):
    def setUp(self):
        super().setUp()
        self.run_cli(["preflight", *self.cloudflare_args(), "--out", str(self.receipt)])
        self.stage()
        self.undo_patch = self.root / "undo.patch.json"

    def undo(self, *extra):
        return self.run_cli(["undo", "--compose", str(self.compose), "--target", str(self.target),
                             "--patch-out", str(self.undo_patch), *self.verify_args(expect="restored")[2:], *extra])

    def test_emits_reverse_patch_and_verify_without_changing_compose_by_default(self):
        staged = self.compose.read_bytes()
        code, out, err = self.undo()
        self.assertEqual(code, 0, err)
        result = json.loads(out)
        self.assertEqual(result["payload"], {"compose": {"port_policy": None}})
        self.assertEqual(json.loads(self.undo_patch.read_text()), result["payload"])
        self.assertEqual(self.undo_patch.stat().st_mode & 0o777, 0o600)
        self.assertEqual(result["phala_command_for_authorized_operator"],
                         f"phala api /cvms/cvm_local -X PATCH --input {self.undo_patch}")
        self.assertIn("verify --expect restored", result["then_verify"])
        self.assertIn("HTTP first", " ".join(result["order"]))
        self.assertEqual(self.compose.read_bytes(), staged)

    def test_apply_stages_local_restore_and_refuses_drift_and_loose_snapshot(self):
        current = json.loads(self.compose.read_text())
        current["port_policy"] = {"restrict_mode": False, "ports": []}
        self.save(self.compose, current)
        self.assertEqual(self.undo("--apply")[0], 1)
        self.assertFalse(self.undo_patch.exists())
        self.undo_patch.unlink(missing_ok=True)
        current["port_policy"] = json.loads(self.snapshot.read_text())["after"]
        self.save(self.compose, current)
        self.snapshot.chmod(0o644)
        self.assertEqual(self.undo("--apply")[0], 1)
        self.snapshot.chmod(0o600)
        self.undo_patch.unlink(missing_ok=True)
        code, out, err = self.undo("--apply")
        self.assertEqual(code, 0, err)
        self.assertIsNone(json.loads(self.compose.read_text())["port_policy"])

    def test_refuses_to_overwrite_an_existing_patch_file(self):
        self.undo_patch.write_text("{}")
        self.assertEqual(self.undo()[0], 1)
        self.assertEqual(self.undo_patch.read_text(), "{}")


class OutputAndClientTest(Base):
    def test_no_secret_or_full_node_id_in_any_output(self):
        outputs = []
        outputs += self.run_cli(["preflight", *self.cloudflare_args(), "--out", str(self.receipt)])[1:]
        outputs += self.run_cli(["plan", *self.cloudflare_args(), *self.switch_args()])[1:]
        self.stage()
        outputs += self.run_cli(["verify", *self.verify_args()])[1:]
        outputs += self.run_cli(["undo", "--compose", str(self.compose), "--target", str(self.target),
                                 "--patch-out", str(self.root / "u.json"), *self.verify_args(expect="restored")[2:]])[1:]
        self.cf.state["tunnel"]["status"] = "down"
        outputs += self.run_cli(["plan", *self.cloudflare_args(), "--compose", str(self.compose), "--target",
                                 str(self.target), "--network", str(self.network), "--snapshot",
                                 str(self.root / "other.json")])[1:]
        text = "\n".join(outputs)
        self.assertTrue(text.strip())
        for secret in (SECRET, NODE, CF_TOKEN):
            self.assertNotIn(secret, text)
        self.assertIn(cf_only.fingerprint(NODE), text)

    def test_cli_refuses_without_a_cloudflare_read_token_before_any_network(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "preflight", *self.cloudflare_args()], text=True,
                                capture_output=True, env={"PATH": "/usr/bin:/bin"})
        self.assertEqual(result.returncode, 1)
        self.assertIn("CLOUDFLARE_READ_TOKEN", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_cloudflare_reader_is_get_only_and_never_leaks_its_token(self):
        seen = []

        class Reply(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def opener(request, timeout):
            seen.append((request.get_method(), request.full_url, request.get_header("Authorization")))
            if "workers/routes" in request.full_url:
                return Reply(json.dumps({"success": True, "result": [{"pattern": "node.tinycloud.xyz/*",
                                                                     "script": "s", "id": "ignored"}]}).encode())
            if "deployments" in request.full_url:
                return Reply(json.dumps({"success": True, "result": {"deployments": [
                    {"versions": [{"version_id": "v9", "percentage": 100}]}]}}).encode())
            if request.full_url.endswith("/settings"):
                return Reply(json.dumps({"success": True, "result": {"bindings": [
                    {"name": "ORIGIN_URL", "type": "secret_text"}]}}).encode())
            return Reply(json.dumps({"success": True, "result": {"id": TUNNEL}}).encode())

        reader = cf_only.CloudflareReader(CF_TOKEN, "acct", "zone", opener=opener)
        worker = reader.worker("s")
        self.assertEqual(worker, {"version_id": "v9", "origin_binding": "secret_text",
                                  "routes": [{"pattern": "node.tinycloud.xyz/*", "script": "s"}]})
        self.assertEqual(reader.tunnel(TUNNEL), {"id": TUNNEL})
        self.assertTrue(seen and all(m == "GET" and a == f"Bearer {CF_TOKEN}" for m, u, a in seen))

        def split_versions(request, timeout):
            if "deployments" in request.full_url:
                return Reply(json.dumps({"success": True, "result": {"deployments": [{"versions": [
                    {"version_id": "a", "percentage": 50}, {"version_id": "b", "percentage": 50}]}]}}).encode())
            return opener(request, timeout)

        self.assertIsNone(cf_only.CloudflareReader(CF_TOKEN, "acct", "zone", opener=split_versions).worker("s")["version_id"])

        for failure in (HTTPError("u", 403, "denied " + CF_TOKEN, {}, None), URLError("boom " + CF_TOKEN)):
            def failing(request, timeout, failure=failure):
                raise failure
            with self.assertRaises(cf_only.ClientError) as caught:
                cf_only.CloudflareReader(CF_TOKEN, "acct", "zone", opener=failing).tunnel(TUNNEL)
            self.assertNotIn(CF_TOKEN, str(caught.exception))

    def test_worker_origin_binding_is_read_by_name_and_type_only(self):
        class Reply(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def reader_with(bindings):
            def opener(request, timeout):
                url = request.full_url
                self.assertEqual(request.get_method(), "GET")
                self.assertNotIn("/content", url)  # the source is never read
                if url.endswith("/settings"):
                    return Reply(json.dumps({"success": True, "result": {"bindings": bindings}}).encode())
                if "deployments" in url:
                    return Reply(json.dumps({"success": True, "result": {"deployments": [
                        {"versions": [{"version_id": "v9", "percentage": 100}]}]}}).encode())
                return Reply(json.dumps({"success": True, "result": []}).encode())
            return cf_only.CloudflareReader(CF_TOKEN, "acct", "zone", opener=opener)

        var = {"name": "ORIGIN_URL", "type": "secret_text"}
        self.assertEqual(reader_with([{"name": "OTHER", "type": "plain_text", "text": "x"}, var]).worker("s")["origin_binding"],
                         "secret_text")
        self.assertEqual(reader_with([dict(var, type="plain_text", text="https://x.example.test")]).worker("s")["origin_binding"],
                         "plain_text")
        for name, bindings in {"absent": [], "other name only": [dict(var, name="PHALA_ORIGIN")],
                               "duplicated": [var, dict(var, type="plain_text")], "no type": [{"name": "ORIGIN_URL"}]}.items():
            with self.subTest(name):
                self.assertIsNone(reader_with(bindings).worker("s")["origin_binding"])

    def test_preflight_requires_the_secret_binding_and_the_operator_attestation(self):
        for name, kind, message in (("plain_text var", "plain_text", "approved path is a secret"),
                                    ("absent or duplicated", None, "no single secret_text"),
                                    ("other type", "json", "no single secret_text")):
            with self.subTest(name):
                self.cf.state["worker"]["origin_binding"] = kind
                code, out, err = self.run_cli(["preflight", *self.cloudflare_args()])
                self.assertEqual(code, 1, out)
                self.assertIn(message, err)
        self.cf.state["worker"]["origin_binding"] = "secret_text"
        unattested = [a for a in self.cloudflare_args() if a != "--attest-origin-is-tunnel-host"]
        code, out, err = self.run_cli(["preflight", *unattested])
        self.assertEqual(code, 1)
        self.assertIn("attest", err)

    def test_phala_tunnel_host_is_refused_even_with_a_secret_binding_and_attestation(self):
        phala = f"{APP}-8000.dstack-pha-prod5.phala.network"
        args = [phala if a == HOST else a for a in self.cloudflare_args()]
        code, out, err = self.run_cli(["preflight", *args])
        self.assertEqual(code, 1)
        self.assertIn("independent tunnel hostname", err)
        self.assertEqual(self.cf.calls, [])

    def test_origin_value_is_recorded_as_unverified_operator_attestation(self):
        code, out, err = self.run_cli(["plan", *self.cloudflare_args(), *self.switch_args()])
        self.assertEqual(code, 0, err)
        evidence = json.loads(out)["evidence"]
        self.assertEqual(evidence["worker_origin_binding"], "secret_text")
        self.assertIn("NOT verified", evidence["worker_origin_value"])
        self.assertIn("operator-attested", evidence["worker_origin_value"])

    def test_verify_states_what_the_end_to_end_checks_can_and_cannot_show(self):
        self.run_cli(["preflight", *self.cloudflare_args(), "--out", str(self.receipt)])
        self.stage()
        code, out, err = self.run_cli(["verify", *self.verify_args()])
        self.assertEqual(code, 0, out)
        result = json.loads(out)
        self.assertIn("NOT verified", result["worker_origin_value"])
        self.assertIn("some route other than the closed gateway", result["what_the_end_to_end_checks_can_show"])
        self.assertTrue(any("secret equals the tunnel host" in c for c in result["what_they_cannot_show"]))
        self.assertTrue(any("before the restriction" in c for c in result["what_they_cannot_show"]))


if __name__ == "__main__":
    unittest.main()
