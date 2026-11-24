#!/usr/bin/env python3
"""Contracts for ingress-cf-only.py: no Cloudflare, no Phala, no external network.

The real ingress-switch.py runs as a local subprocess on temporary files. Cloudflare and
HTTP/probe clients are fakes, except NetworkProbe's classifier, which is exercised against
a localhost-only TLS server (self-signed certificate generated at run time).
"""
import contextlib
from datetime import datetime, timedelta, timezone
import importlib.util
import io
import json
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
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
ACCT = "c" * 32
ZONE = "d" * 32
NODE = "did:key:z6MkCanaryNodeId"
OTHER_NODE = "did:key:z6MkOtherNode"
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


ADDR = {"ipv4": "192.0.2.10", "ipv6": "2001:db8::10"}  # one SNI-routed gateway address per family, shared by every host
INSTANCE_MGMT = f"{INSTANCE}-10022.{GATEWAY}"


class FakeHttp:
    """Models a restricted gateway by default; override per host to model other signals."""

    def __init__(self, restricted=True):
        self.info_map = {HOST: {"status": 200, "node_id": NODE}, "node.tinycloud.xyz": {"status": 200, "node_id": NODE}}
        self.probe_map = {}
        self.restricted = restricted
        self.mgmt = {"outcome": "ssh_banner"}
        self.mgmt6 = {"outcome": "ssh_banner"}
        self.mgmt_calls = []
        self.instance_mgmt = {"outcome": "ssh_banner"}
        self.controls = {}  # address -> signal of the same-address positive control (default: ssh_banner)
        self.control_calls = []
        self.probes = []

    def info(self, host):
        return self.info_map.get(host, {"status": None, "node_id": None})

    def probe(self, host, family, port=443):
        self.probes.append((host, family, port))
        if (host, family) in self.probe_map:
            result = self.probe_map[(host, family)]
        else:
            result = {"outcome": "tcp_refused"} if self.restricted else {"outcome": "node_info", "node_id": NODE}
        if "addresses" not in result and result["outcome"] not in ("no_address", "no_aaaa"):
            signals = result.get("signals") or [result["outcome"]]
            result = dict(result, addresses=[ADDR[family]] * len(signals))
        return result

    def mgmt_probe(self, host, family="ipv4", port=443):
        assert port == 443 and (host == MGMT or (host == INSTANCE_MGMT and family == "ipv4")), (host, family, port)
        self.mgmt_calls.append((host, family))
        if host == INSTANCE_MGMT:
            return self.instance_mgmt
        return self.mgmt if family == "ipv4" else self.mgmt6

    def control(self, address, family, sni):
        assert sni == MGMT, sni
        self.control_calls.append((address, family))
        return self.controls.get(address, "ssh_banner")


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
        self.receipt_out = self.root / "receipt-from-apply.json"
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
                "--account-id", ACCT, "--zone-id", ZONE, "--attest-origin-is-tunnel-host"]

    def switch_args(self):
        return ["--compose", str(self.compose), "--target", str(self.target), "--network", str(self.network),
                "--snapshot", str(self.snapshot)]

    def verify_args(self, *extra, expect="restricted", receipt=None):
        return ["--expect", expect, "--expect-app-id", APP, "--instance-id", INSTANCE, "--gateway-domain", GATEWAY,
                "--tunnel-host", HOST, "--snapshot", str(self.snapshot), "--receipt", str(receipt or self.receipt),
                *extra]

    def run_cli(self, argv, now=None):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cf_only.main(argv, clients=self.clients(), now=now, out=out)
        return code, out.getvalue(), err.getvalue()

    def plan(self):
        code, out, err = self.run_cli(["plan", *self.cloudflare_args(), *self.switch_args()])
        self.assertEqual(code, 0, err)
        return json.loads(out)

    def apply_args(self, digest, patch=None, receipt_out=None):
        return ["apply-patch", *self.cloudflare_args(), *self.switch_args(), "--confirm", digest,
                "--patch-out", str(patch or self.patch), "--receipt-out", str(receipt_out or self.receipt_out)]

    def stage(self):
        code, out, err = self.run_cli(self.apply_args(self.plan()["plan_hash"]))
        self.assertEqual(code, 0, err)
        return json.loads(out)

    def set_node_ids(self, node):
        self.http.info_map[HOST]["node_id"] = self.http.info_map["node.tinycloud.xyz"]["node_id"] = node


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
        self.assertIn("healthy", saved["connector_authenticated_basis"])
        self.assertEqual((saved["origin_status"], saved["public_status"]), (200, 200))
        self.assertIn("not a cryptographic attestation", saved["evidence_label"])
        self.assertIn("not a cryptographic attestation", out)
        self.assertEqual(sorted(self.cf.calls), ["dns", "ingress", "tunnel", "worker"])

    def test_refuses_on_each_mismatch_or_missing_evidence(self):
        cases = {
            "other tunnel": lambda s, h: s["tunnel"].update(id="99999999-2222-4333-8444-555555555555"),
            "deleted tunnel": lambda s, h: s["tunnel"].update(deleted_at="2026-01-01T00:00:00Z"),
            "degraded": lambda s, h: s["tunnel"].update(status="degraded"),
            "no connections": lambda s, h: s["tunnel"].update(connections=[]),
            "pending reconnect": lambda s, h: s["tunnel"]["connections"][0].update(is_pending_reconnect=True),
            "ingress wrong service": lambda s, h: s["ingress"][0].update(service="http://elsewhere:80"),
            "ingress missing host": lambda s, h: s["ingress"][0].update(hostname="other.example.test"),
            "ingress not a list": lambda s, h: s.update(ingress={"hostname": HOST}),
            "ingress catch-all shadows the host": lambda s, h: s["ingress"].insert(0, {"service": "http_status:404"}),
            "ingress path-scoped rule": lambda s, h: s["ingress"][0].update(path="^/only"),
            "dns missing": lambda s, h: s.update(dns=[]),
            "dns other tunnel": lambda s, h: s["dns"][0].update(content="x.cfargotunnel.com"),
            "dns not proxied": lambda s, h: s["dns"][0].update(proxied=False),
            "dns duplicated": lambda s, h: s["dns"].append(dict(s["dns"][0])),
            "worker origin is a plain_text var": lambda s, h: s["worker"].update(origin_binding="plain_text"),
            "worker origin binding absent": lambda s, h: s["worker"].update(origin_binding=None),
            "worker version unreadable": lambda s, h: s["worker"].update(version_id=None),
            "node route missing": lambda s, h: s["worker"].update(routes=[]),
            "node route other script": lambda s, h: s["worker"]["routes"][0].update(script="other"),
            "more specific node route to another script": lambda s, h: s["worker"]["routes"].append(
                {"pattern": "node.tinycloud.xyz/admin/*", "script": "other"}),
            "origin info unhealthy": lambda s, h: h.info_map[HOST].update(status=503),
            "public info unreachable": lambda s, h: h.info_map.pop("node.tinycloud.xyz"),
            "node ids differ": lambda s, h: h.info_map[HOST].update(node_id=OTHER_NODE),
            "node id missing": lambda s, h: [h.info_map[k].update(node_id=None) for k in list(h.info_map)],
        }
        for name, fn in cases.items():
            with self.subTest(name):
                self.cf, self.http = FakeCf(), FakeHttp()
                fn(self.cf.state, self.http)
                code, out, err = self.run_cli(["preflight", *self.cloudflare_args(), "--out", str(self.receipt)])
                self.assertEqual(code, 4, out)
                self.assertFalse(self.receipt.exists())

    def test_refuses_bad_arguments_before_any_read(self):
        base = self.cloudflare_args()

        def swap(old, new):
            return [new if a == old else a for a in base]

        for name, argv in {
            "version": [*base, "--expect-worker-version", "ver-0"],
            "tunnel id": swap(TUNNEL, "not-a-uuid"),
            "phala host": swap(HOST, f"{APP}-8000.dstack.phala.network"),
            "public host": swap(HOST, "node.tinycloud.xyz"),
            "tee host": swap(HOST, "tee.node.tinycloud.xyz"),
            "cfargotunnel host": swap(HOST, f"{TUNNEL}.cfargotunnel.com"),
            "non-hex app id": swap(APP, "z" * 40),
            "short account id": swap(ACCT, "acct"),
            "path-injecting zone id": swap(ZONE, "../" + "d" * 29),
            "path-injecting script": [*base, "--worker-script", "a/../../b"],
        }.items():
            with self.subTest(name):
                self.cf = FakeCf()
                code, out, err = self.run_cli(["preflight", *argv])
                self.assertEqual(code, 4, out)
                if name != "version":
                    self.assertEqual(self.cf.calls, [])

    def test_preflight_requires_the_secret_binding_and_the_operator_attestation(self):
        for name, kind, message in (("plain_text var", "plain_text", "approved path is a secret"),
                                    ("absent or duplicated", None, "no single secret_text"),
                                    ("other type", "json", "no single secret_text")):
            with self.subTest(name):
                self.cf.state["worker"]["origin_binding"] = kind
                code, out, err = self.run_cli(["preflight", *self.cloudflare_args()])
                self.assertEqual(code, 4, out)
                self.assertIn(message, err)
        self.cf.state["worker"]["origin_binding"] = "secret_text"
        unattested = [a for a in self.cloudflare_args() if a != "--attest-origin-is-tunnel-host"]
        code, out, err = self.run_cli(["preflight", *unattested])
        self.assertEqual(code, 4)
        self.assertIn("attest", err)

    def test_a_failed_read_is_exit_4_not_1(self):
        def fail(*args, **kwargs):
            raise cf_only.ClientError("Cloudflare read failed")
        self.cf.tunnel = fail
        code, out, err = self.run_cli(["preflight", *self.cloudflare_args(), "--out", str(self.receipt)])
        self.assertEqual((code, out), (4, ""))
        self.assertIn("Nothing was changed or judged", err)
        self.assertFalse(self.receipt.exists())

    def test_receipt_path_must_be_new_and_writable_before_any_read(self):
        self.receipt.write_text("{}")
        self.assertEqual(self.run_cli(["preflight", *self.cloudflare_args(), "--out", str(self.receipt)])[0], 4)
        self.assertEqual(self.receipt.read_text(), "{}")
        self.assertEqual(self.run_cli(["preflight", *self.cloudflare_args(), "--out", str(self.root / "no" / "r.json")])[0], 4)
        self.assertEqual(self.cf.calls, [])


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

    def test_origin_value_is_recorded_as_unverified_operator_attestation(self):
        evidence = self.plan()["evidence"]
        self.assertEqual(evidence["worker_origin_binding"], "secret_text")
        self.assertIn("NOT verified", evidence["worker_origin_value"])
        self.assertIn("operator-attested", evidence["worker_origin_value"])

    def test_plan_hash_is_stable_and_changes_with_node_id_worker_version_and_compose(self):
        base = self.plan()["plan_hash"]
        self.assertEqual(self.plan()["plan_hash"], base)
        self.set_node_ids(OTHER_NODE)
        self.assertNotEqual(self.plan()["plan_hash"], base)
        self.set_node_ids(NODE)
        self.cf.state["worker"]["version_id"] = "ver-2"
        self.assertNotEqual(self.plan()["plan_hash"], base)
        self.cf.state["worker"]["version_id"] = "ver-1"
        self.save(self.compose, dict(self.original, unrelated=1))
        self.assertNotEqual(self.plan()["plan_hash"], base)

    def test_apply_patch_requires_matching_confirm_and_never_calls_phala(self):
        digest = self.plan()["plan_hash"]
        for confirm in ("0" * 64, digest[:-1], ""):
            with self.subTest(confirm=confirm):
                code, out, err = self.run_cli(self.apply_args(confirm))
                self.assertEqual(code, 4)
                self.assertFalse(self.snapshot.exists() or self.patch.exists() or self.receipt_out.exists())
                self.assertEqual(json.loads(self.compose.read_text()), self.original)
        spawned = []
        real_run = subprocess.run

        def record(argv, **kwargs):
            spawned.append(argv)
            return real_run(argv, **kwargs)

        with mock.patch.object(cf_only.subprocess, "run", record):
            code, out, err = self.run_cli(self.apply_args(digest))
        self.assertEqual(code, 0, err)
        self.assertTrue(spawned and all(Path(a[1]).name == "ingress-switch.py" for a in spawned))
        result = json.loads(out)
        self.assertEqual(result["phala_command_for_authorized_operator"],
                         f"phala api /cvms/cvm_local -X PATCH --input {self.patch}")
        self.assertIn("NO Phala call", result["executed_by_this_script"])
        self.assertEqual(json.loads(self.patch.read_text()), result["payload"])
        self.assertEqual(result["payload"]["compose"]["port_policy"]["restrict_mode"], True)
        for private in (self.snapshot, self.patch, self.receipt_out):
            self.assertEqual(private.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(self.compose.read_text())["port_policy"]["restrict_mode"], True)
        # The verify command carries every value quoted, the real receipt path, and quoted placeholders.
        self.assertIn(f"--receipt {self.receipt_out}", result["then_verify"])
        self.assertIn("--instance-id '<INSTANCE-ID>'", result["then_verify"])
        self.assertIn("--gateway-domain '<GATEWAY-DOMAIN>'", result["then_verify"])

    def test_confirm_goes_stale_when_evidence_changes_between_plan_and_apply(self):
        digest = self.plan()["plan_hash"]
        self.set_node_ids(OTHER_NODE)
        code, out, err = self.run_cli(self.apply_args(digest))
        self.assertEqual(code, 4)
        self.assertFalse(self.snapshot.exists() or self.patch.exists())

    def test_unwritable_output_path_is_refused_before_anything_is_staged(self):
        digest = self.plan()["plan_hash"]
        code, out, err = self.run_cli(self.apply_args(digest, patch=self.root / "missing-dir" / "p.json"))
        self.assertEqual(code, 4)
        self.assertFalse(self.snapshot.exists())
        self.assertEqual(json.loads(self.compose.read_text()), self.original)
        self.receipt_out.write_text("{}")
        self.assertEqual(self.run_cli(self.apply_args(digest))[0], 4)
        self.assertFalse(self.snapshot.exists())

    def test_plan_and_apply_refuse_when_preflight_refuses(self):
        self.cf.state["tunnel"]["status"] = "down"
        code, out, err = self.run_cli(["plan", *self.cloudflare_args(), *self.switch_args()])
        self.assertEqual(code, 4)
        self.assertEqual(out, "")

    def test_the_rollback_snapshot_marks_the_origin_as_attested_not_verified_and_nothing_prints_verified(self):
        plan_out = self.run_cli(["plan", *self.cloudflare_args(), *self.switch_args()])[1]
        result = self.stage()
        snap = json.loads(self.snapshot.read_text())
        self.assertEqual(self.snapshot.stat().st_mode & 0o777, 0o600)
        self.assertEqual(snap["verified_origin"]["worker_origin"], f"https://{HOST}")
        self.assertIn("NOT verified", snap["verified_origin"]["worker_origin_status"])
        self.assertIn("operator-attested", snap["verified_origin_note"])
        self.assertEqual(snap["after"]["restrict_mode"], True)
        self.assertFalse(list(self.root.glob("*.annotating")))
        # Only the negated phrase may contain the word; the switch's own key name is not printed here.
        for text in (plan_out, json.dumps(result)):
            self.assertNotIn("verified", text.replace("NOT verified", ""))


class VerifyTest(Base):
    def setUp(self):
        super().setUp()
        # TEST-ONLY: inject accepted closed signatures so the control mechanism is exercised. The shipped set is empty
        # (DefaultClosedSetTest) and nothing on the CLI can reach this name.
        patcher = mock.patch.object(cf_only, "ACCEPTED_CLOSED_SIGNALS", ("tcp_refused", "tcp_reset"))
        patcher.start()
        self.addCleanup(patcher.stop)
        code, out, err = self.run_cli(["preflight", *self.cloudflare_args(), "--out", str(self.receipt)])
        self.assertEqual(code, 0, err)
        self.stage()

    def verify(self, *extra, expect="restricted", now=None, receipt=None):
        return self.run_cli(["verify", *self.verify_args(*extra, expect=expect, receipt=receipt)], now=now)

    def not_passed(self, out):
        return [c["check"] for c in json.loads(out)["checks"] if c["status"] != "pass"]

    def all_probe_hosts(self):
        return cf_only.direct_hosts(mock.Mock(expect_app_id=APP, instance_id=INSTANCE, gateway_domain=GATEWAY,
                                              extra_host=None))

    def test_passes_when_every_condition_holds_over_ipv4_and_ipv6(self):
        code, out, err = self.verify()
        self.assertEqual(code, 0, out)
        result = json.loads(out)
        self.assertEqual(result["result"], "pass")
        self.assertEqual(result["accepted_closed_signals"], ["tcp_refused", "tcp_reset"])
        probed = {(h, f) for h, f, p in self.http.probes}
        for host in (cf_only.TEE_HOST, f"{APP}-443s.{GATEWAY}", f"{INSTANCE}-443s.{GATEWAY}",
                     f"{APP}-8000.{GATEWAY}", f"{INSTANCE}-443.{GATEWAY}"):
            for family in ("ipv4", "ipv6"):
                self.assertIn((host, family), probed)
        self.assertTrue(result["not_covered"])
        self.assertIn("ACCEPTED closed signature", result["closed_rule"])
        self.assertIn((MGMT, "ipv6"), self.http.mgmt_calls)  # management is covered over IPv6 too

    def test_verify_works_from_the_receipt_written_by_apply_patch(self):
        self.assertEqual(self.verify(receipt=self.receipt_out)[0], 0)

    def test_fails_on_each_condition_and_never_reports_indeterminate(self):
        node = {"outcome": "node_info", "node_id": NODE}
        cases = {
            "tee ipv4 still serves": (lambda h: h.probe_map.update({(cf_only.TEE_HOST, "ipv4"): node}),
                                      "tee.node.tinycloud.xyz fresh ipv4"),
            "instance -443s ipv6 still serves": (lambda h: h.probe_map.update({(f"{INSTANCE}-443s.{GATEWAY}", "ipv6"): node}),
                                                 "-443s.gw.example.test fresh ipv6"),
            "multi-address answer with one node response": (lambda h: h.probe_map.update({
                (cf_only.TEE_HOST, "ipv4"): {"outcome": "node_info", "signals": ["tcp_refused", "node_info"]}}),
                "tee.node.tinycloud.xyz fresh ipv4"),
            "timeout is unknown": (lambda h: h.probe_map.update({(f"{APP}-8000.{GATEWAY}", "ipv4"):
                                   {"outcome": "timeout"}}), f"{APP}-8000"),
            "gateway 502 completed HTTP": (lambda h: h.probe_map.update({(f"{APP}-443.{GATEWAY}", "ipv4"):
                                           {"outcome": "http_502"}}), f"{APP}-443."),
            "404 completed HTTP": (lambda h: h.probe_map.update({(f"{APP}-443s.{GATEWAY}", "ipv4"):
                                   {"outcome": "http_404"}}), f"{APP}-443s."),
            "421 completed HTTP": (lambda h: h.probe_map.update({(f"{APP}-443s.{GATEWAY}", "ipv4"):
                                   {"outcome": "http_421"}}), f"{APP}-443s."),
            "tls alert completed TLS": (lambda h: h.probe_map.update({(cf_only.TEE_HOST, "ipv4"):
                                        {"outcome": "tls_rejected"}}), "tee.node.tinycloud.xyz"),
            "close after TLS": (lambda h: h.probe_map.update({(cf_only.TEE_HOST, "ipv4"):
                                {"outcome": "closed_after_tls"}}), "tee.node.tinycloud.xyz"),
            "unparsed 200": (lambda h: h.probe_map.update({(cf_only.TEE_HOST, "ipv4"):
                             {"outcome": "http_200_unparsed"}}), "tee.node.tinycloud.xyz"),
            "generic error": (lambda h: h.probe_map.update({(cf_only.TEE_HOST, "ipv4"):
                              {"outcome": "error"}}), "tee.node.tinycloud.xyz"),
            "ipv4 resolver error": (lambda h: h.probe_map.update({(f"{APP}-443.{GATEWAY}", "ipv4"):
                                    {"outcome": "no_address"}}), f"{APP}-443."),
            "ipv6 without AAAA is unverified": (lambda h: h.probe_map.update({(cf_only.TEE_HOST, "ipv6"):
                                                {"outcome": "no_address"}}), "tee.node.tinycloud.xyz fresh ipv6"),
            "AAAA missing without the waiver": (lambda h: h.probe_map.update({(cf_only.TEE_HOST, "ipv6"):
                                                {"outcome": "no_aaaa"}}), "tee.node.tinycloud.xyz fresh ipv6"),
            "no route": (lambda h: h.probe_map.update({(cf_only.TEE_HOST, "ipv4"):
                                                       {"outcome": "no_route"}}), "tee.node.tinycloud.xyz fresh ipv4"),
            "reset once connected (RST after ClientHello)": (lambda h: h.probe_map.update({(cf_only.TEE_HOST, "ipv4"):
                                                             {"outcome": "reset_after_connect"}}),
                                                             "tee.node.tinycloud.xyz fresh ipv4"),
            "node.* unhealthy": (lambda h: h.info_map["node.tinycloud.xyz"].update(status=502),
                                 "node.tinycloud.xyz /info"),
            "node ids differ": (lambda h: h.info_map[HOST].update(node_id=OTHER_NODE), "tunnel host /info"),
            "management looks closed while it must stay open": (lambda h: setattr(h, "mgmt", {"outcome": "tcp_refused"}),
                                                                "management route"),
            "management timeout": (lambda h: setattr(h, "mgmt", {"outcome": "timeout"}), "management route"),
            "management answers a non-SSH protocol": (lambda h: setattr(h, "mgmt", {"outcome": "non_ssh_data"}),
                                                      "management route"),
            "management ipv6 times out": (lambda h: setattr(h, "mgmt6", {"outcome": "timeout"}), "over ipv6"),
            "management ipv6 refused": (lambda h: setattr(h, "mgmt6", {"outcome": "tcp_refused"}), "over ipv6"),
            "management ipv6 no route": (lambda h: setattr(h, "mgmt6", {"outcome": "no_route"}), "over ipv6"),
            "management ipv6 AAAA missing without the waiver": (lambda h: setattr(h, "mgmt6", {"outcome": "no_aaaa"}),
                                                                "over ipv6"),
        }
        for name, (fn, expected) in cases.items():
            with self.subTest(name):
                self.http = FakeHttp()
                fn(self.http)
                code, out, err = self.verify()
                open_class = ("tee ipv4 still serves", "instance -443s ipv6 still serves", "multi-address answer with one node "
                              "response", "node.* unhealthy", "node ids differ", "management answers a non-SSH protocol",
                              "unparsed 200")
                self.assertEqual(code, 1 if name in open_class else 3, out)
                self.assertEqual(json.loads(out)["verdict"], "open" if name in open_class else "not_proven_closed")
                self.assertEqual(json.loads(out)["result"], "FAIL")
                self.assertTrue(any(expected in c for c in self.not_passed(out)), self.not_passed(out))

    def test_only_refused_and_reset_are_accepted_in_this_patched_set_and_the_accept_flag_no_longer_exists(self):
        self.http.probe_map[(cf_only.TEE_HOST, "ipv4")] = {"outcome": "tcp_reset"}
        self.http.probe_map[(f"{APP}-443s.{GATEWAY}", "ipv6")] = {"outcome": "tcp_reset"}
        code, out, err = self.verify()
        self.assertEqual(code, 0, out)
        self.assertEqual(json.loads(out)["accepted_closed_signals"], ["tcp_refused", "tcp_reset"])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.verify("--accept-closed-signal", "http_421")

    def test_no_route_is_not_closed_over_ipv4_or_ipv6_even_with_the_aaaa_waiver(self):
        for family in ("ipv4", "ipv6"):
            for flags in ((), ("--allow-no-aaaa",)):
                with self.subTest(family=family, flags=flags):
                    self.http = FakeHttp()
                    self.http.probe_map[(f"{APP}-443s.{GATEWAY}", family)] = {"outcome": "no_route"}
                    code, out, err = self.verify(*flags)
                    self.assertEqual(code, 3, out)
                    self.assertTrue(any(f"{APP}-443s." in c and family in c for c in self.not_passed(out)))

    def test_management_ipv6_nodata_is_waived_only_by_the_flag_and_a_present_aaaa_must_answer(self):
        self.http.mgmt6 = {"outcome": "no_aaaa"}
        self.assertEqual(self.verify()[0], 3)
        code, out, err = self.verify("--allow-no-aaaa")
        self.assertEqual(code, 0, out)
        self.assertEqual(json.loads(out)["waivers"]["hosts_waived"], [MGMT])
        for outcome in ("timeout", "tcp_refused", "no_route", "tls_rejected", "non_ssh_data", "no_address"):
            with self.subTest(outcome):
                self.http.mgmt6 = {"outcome": outcome}
                code, out, err = self.verify("--allow-no-aaaa")
                self.assertEqual(code, 1 if outcome in ("tls_rejected", "non_ssh_data") else 3, out)
                self.assertTrue(any("over ipv6" in c and "management" in c for c in self.not_passed(out)))
        # IPv4 management is never waived.
        self.http.mgmt6 = {"outcome": "ssh_banner"}
        self.http.mgmt = {"outcome": "no_aaaa"}
        self.assertEqual(self.verify("--allow-no-aaaa")[0], 3)

    def test_resolved_addresses_and_controls_are_recorded_per_check_in_the_receipt(self):
        code, out, err = self.verify()
        self.assertEqual(code, 0, out)
        runs = json.loads(self.receipt.read_text())["verify_runs"]
        self.assertEqual(len(runs), 1)
        closed = [c for c in runs[0]["checks"] if "accepted closed signature" in c["check"]]
        self.assertTrue(closed)
        for c in closed:
            family = "ipv6" if " ipv6 " in c["check"] else "ipv4"
            self.assertEqual((c["addresses"], c["controls"]), ([ADDR[family]], {ADDR[family]: "ssh_banner"}))
        self.assertEqual(self.receipt.stat().st_mode & 0o777, 0o600)

    def test_allow_no_aaaa_waives_only_dns_nodata_and_records_the_waiver_in_the_receipt(self):
        nodata = {(h, "ipv6"): {"outcome": "no_aaaa"} for h in self.all_probe_hosts()}
        self.http.probe_map = dict(nodata)
        self.assertEqual(self.verify()[0], 3)  # no flag: NODATA is not closed
        self.assertNotIn("verify_waivers", json.loads(self.receipt.read_text()))
        code, out, err = self.verify("--allow-no-aaaa")
        self.assertEqual(code, 0, out)
        self.assertIn("not proof of no IPv6 path", out)
        printed = json.loads(out)["waivers"]
        recorded = json.loads(self.receipt.read_text())["verify_waivers"]
        self.assertEqual(recorded, [printed])
        self.assertEqual((printed["waiver"], sorted(printed["hosts_waived"])), ("allow-no-aaaa", sorted(self.all_probe_hosts())))
        self.assertEqual(self.receipt.stat().st_mode & 0o777, 0o600)
        self.assertFalse(list(self.root.glob("*.record")))
        self.assertEqual(json.loads(self.verify()[1])["waivers"], "none (--allow-no-aaaa not given)")

    def test_the_waiver_does_not_cover_a_present_aaaa_record_or_a_resolver_error(self):
        host = f"{APP}-443s.{GATEWAY}"
        for name, outcome in (("AAAA present, v6 connect gives no route", {"outcome": "no_route"}),
                              ("AAAA present, v6 answers HTTP", {"outcome": "http_404"}),
                              ("AAAA present, v6 times out", {"outcome": "timeout"}),
                              ("resolver error or NXDOMAIN", {"outcome": "no_address"})):
            with self.subTest(name):
                self.http = FakeHttp()
                self.http.probe_map[(host, "ipv6")] = outcome
                code, out, err = self.verify("--allow-no-aaaa")
                self.assertEqual(code, 3, out)
                self.assertTrue(any(host in c and "ipv6" in c for c in self.not_passed(out)))
                self.assertNotIn(host, json.loads(out)["waivers"]["hosts_waived"])
        # A waived host elsewhere does not rescue a failing one, and the waiver stays scoped to ipv6.
        self.http = FakeHttp()
        self.http.probe_map[(cf_only.TEE_HOST, "ipv4")] = {"outcome": "no_aaaa"}
        self.assertEqual(self.verify("--allow-no-aaaa")[0], 3)

    def test_refuses_stale_receipt_loose_files_other_app_and_mismatched_tunnel(self):
        self.assertEqual(self.verify(now=datetime.now(timezone.utc) + timedelta(hours=2))[0], 4)
        self.snapshot.chmod(0o644)
        self.assertEqual(self.verify()[0], 4)
        self.snapshot.chmod(0o600)
        self.receipt.chmod(0o644)
        self.assertEqual(self.verify()[0], 4)
        self.receipt.chmod(0o600)
        snap = json.loads(self.snapshot.read_text())
        self.save(self.snapshot, dict(snap, app_id="c" * 40))
        self.assertEqual(self.verify()[0], 4)
        self.save(self.snapshot, dict(snap, verified_origin=dict(snap["verified_origin"], tunnel_id="9" * 8 + TUNNEL[8:])))
        self.assertEqual(self.verify()[0], 4)
        stripped = {k: v for k, v in snap["verified_origin"].items() if k != "worker_origin_status"}
        self.save(self.snapshot, dict(snap, verified_origin=stripped))
        self.assertEqual(self.verify()[0], 4)
        self.save(self.snapshot, snap)
        other = json.loads(self.receipt.read_text())
        self.save(self.receipt, dict(other, tunnel_hostname="other.example.test"))
        self.assertEqual(self.verify()[0], 4)
        self.save(self.receipt, other)
        self.assertEqual(self.verify()[0], 0)

    def test_management_denied_by_the_policy_cannot_be_corroborated_so_verify_fails(self):
        snap = json.loads(self.snapshot.read_text())
        self.save(self.snapshot, dict(snap, after={"restrict_mode": True, "ports": []}))
        for outcome in ("tcp_refused", "ssh_banner", "timeout", "tls_rejected", "http_404"):
            with self.subTest(outcome):
                self.http = FakeHttp()
                self.http.mgmt = self.http.mgmt6 = {"outcome": outcome}
                code, out, err = self.verify()
                self.assertEqual(code, 1 if outcome == "ssh_banner" else 3, out)  # answering although denied is OPEN
                failed = " ".join(self.not_passed(out))
                self.assertIn("management route", failed)
                self.assertIn("--instance-id", failed)  # no known-open SNI exists to bind it either
        self.assertEqual(self.http.control_calls, [])

    def test_a_refusal_counts_only_with_a_same_address_positive_control_and_addresses_are_recorded(self):
        code, out, err = self.verify()
        self.assertEqual(code, 0, out)
        checks = {c["check"]: c for c in json.loads(out)["checks"]}
        refused = [c for c in checks.values() if "accepted closed signature" in c["check"]]
        self.assertTrue(refused)
        for c in refused:
            family = "ipv6" if " ipv6 " in c["check"] else "ipv4"
            self.assertEqual(c["addresses"], [ADDR[family]])
            self.assertEqual(c["controls"], {ADDR[family]: "ssh_banner"})
        # One control per distinct address, over both families, with the real app's management host.
        self.assertEqual(sorted(set(self.http.control_calls)), sorted({(ADDR["ipv4"], "ipv4"), (ADDR["ipv6"], "ipv6")}))
        self.assertEqual(len(self.http.control_calls), 2)

    def test_a_refusal_the_gateway_cannot_have_produced_fails_when_the_control_fails(self):
        # Open gateway plus a local or on-path REJECT: every refusal looks closed, but the same address does not
        # complete a TLS/SNI connect for the known-open host either, or does not answer SSH.
        for control_signal in ("tcp_refused", "timeout", "tls_rejected", "no_route", "non_ssh_data", "http_404"):
            for family in ("ipv4", "ipv6"):
                with self.subTest(control=control_signal, family=family):
                    self.http = FakeHttp()
                    self.http.controls[ADDR[family]] = control_signal
                    code, out, err = self.verify()
                    self.assertEqual(code, 3, out)
                    bad = [c for c in json.loads(out)["checks"] if c["status"] != "pass"]
                    self.assertTrue(bad and all(family in c["check"] and "positive control" in c["detail"] for c in bad), bad)
                    self.assertTrue(all(c["controls"] == {ADDR[family]: control_signal} for c in bad))

    def test_a_reset_is_closed_only_with_the_control_and_a_missing_address_never_passes(self):
        self.http.probe_map[(cf_only.TEE_HOST, "ipv4")] = {"outcome": "tcp_reset"}
        self.assertEqual(self.verify()[0], 0)
        self.http.controls[ADDR["ipv4"]] = "timeout"
        self.assertEqual(self.verify()[0], 3)
        self.http = FakeHttp()
        self.http.probe_map[(cf_only.TEE_HOST, "ipv4")] = {"outcome": "tcp_refused", "signals": ["tcp_refused"],
                                                           "addresses": []}
        code, out, err = self.verify()
        self.assertEqual(code, 3, out)
        self.assertIn("no resolved address", out)

    def test_an_instance_id_typo_cannot_read_as_closed(self):
        # The gateway answers an unknown instance SNI like a closed one; the typo'd instance has no management route.
        for outcome in ("tcp_refused", "tcp_reset", "tls_rejected", "closed_after_tls", "timeout", "http_404"):
            with self.subTest(outcome):
                self.http = FakeHttp()
                self.http.instance_mgmt = {"outcome": outcome}
                code, out, err = self.verify()
                self.assertEqual(code, 3, out)
                self.assertTrue(any("--instance-id is a real gateway host" in c for c in self.not_passed(out)))

    def test_extra_hosts_must_belong_to_the_app_or_instance(self):
        good = f"{APP}-9999.{GATEWAY}"
        code, out, err = self.verify("--extra-host", good)
        self.assertEqual(code, 0, out)
        self.assertIn(good, [h for h, f, p in self.http.probes])
        for bad in (f"{'c' * 40}-8000.{GATEWAY}", "other.example.test", f"{APP}-8000.elsewhere.example.test"):
            with self.subTest(bad):
                self.http = FakeHttp()
                code, out, err = self.verify("--extra-host", bad)
                self.assertEqual(code, 4)
                self.assertEqual(self.http.probes, [])

    def test_restored_expectation_needs_tee_to_serve_the_same_node(self):
        self.http = FakeHttp(restricted=False)
        code, out, err = self.verify(expect="restored")
        self.assertEqual(code, 0, out)
        self.http.probe_map[(cf_only.TEE_HOST, "ipv4")] = {"outcome": "node_info", "node_id": OTHER_NODE}
        self.assertEqual(self.verify(expect="restored")[0], 1)
        self.http.probe_map[(cf_only.TEE_HOST, "ipv4")] = {"outcome": "tcp_refused"}
        self.assertEqual(self.verify(expect="restored")[0], 1)

    def test_restored_still_probes_management_over_ipv6_so_the_vantage_needs_ipv6_when_an_aaaa_exists(self):
        # S7, decision: restored KEEPS the IPv6 management probe (an AAAA that exists must be probed). From an IPv4-only
        # vantage that is no_route: a vantage limit, so exit 3 (hold), never exit 1 (undo). NODATA needs the flag.
        self.http = FakeHttp(restricted=False)
        self.http.mgmt6 = {"outcome": "no_route"}
        code, out, err = self.verify(expect="restored")
        self.assertEqual((code, json.loads(out)["verdict"]), (3, "not_proven_closed"), out)
        self.assertIn((MGMT, "ipv6"), self.http.mgmt_calls)
        self.assertTrue(any("over ipv6" in c for c in self.not_passed(out)))
        self.http.mgmt6 = {"outcome": "no_aaaa"}
        self.assertEqual(self.verify(expect="restored")[0], 3)
        code, out, err = self.verify("--allow-no-aaaa", expect="restored")
        self.assertEqual(code, 0, out)

    def test_a_vantage_or_dns_limit_on_management_is_never_an_undo_signal(self):
        for expect in ("restricted", "restored"):
            for outcome in ("timeout", "no_route", "no_aaaa", "no_address", "error", "tcp_refused", "tcp_reset"):
                for family in ("ipv4", "ipv6"):
                    with self.subTest(expect=expect, outcome=outcome, family=family):
                        self.http = FakeHttp(restricted=expect == "restricted")
                        setattr(self.http, "mgmt" if family == "ipv4" else "mgmt6", {"outcome": outcome})
                        code, out, err = self.verify(expect=expect)
                        self.assertEqual((code, json.loads(out)["verdict"]), (3, "not_proven_closed"), out)


class DefaultClosedSetTest(Base):
    """The shipped policy: ACCEPTED_CLOSED_SIGNALS is empty, so verify cannot pass for a restricted gateway."""

    def setUp(self):
        super().setUp()
        code, out, err = self.run_cli(["preflight", *self.cloudflare_args(), "--out", str(self.receipt)])
        self.assertEqual(code, 0, err)
        self.applied = self.stage()

    def verify(self, *extra, expect="restricted"):
        return self.run_cli(["verify", *self.verify_args(*extra, expect=expect)])

    def test_not_proven_closed_never_tells_the_operator_to_undo_and_open_does(self):
        after = self.applied["after_verify"]
        self.assertNotIn("if_bad", self.applied)
        self.assertIn("do NOT undo and do NOT restart", after["exit 3"])
        self.assertNotIn("undo --snapshot", after["exit 3"])
        self.assertIn("undo --snapshot", after["exit 1"])
        self.assertIn("NOT PROVEN CLOSED", after["exit 3"])
        code, out, err = self.verify()  # a correct restriction reads not_proven_closed with the empty set
        result = json.loads(out)
        self.assertEqual((code, result["verdict"], result["exit_code"]), (3, "not_proven_closed", 3))
        self.assertIn("Do NOT undo", result["next_action"])
        self.http = FakeHttp(restricted=False)  # the node still answers on the gateway: open
        code, out, err = self.verify()
        result = json.loads(out)
        self.assertEqual((code, result["verdict"]), (1, "open"))
        self.assertNotIn("Do NOT undo", result["next_action"])
        self.assertIn("undo", result["next_action"])
        self.http = FakeHttp()
        snap = json.loads(self.snapshot.read_text())
        self.save(self.snapshot, dict(snap, after={"restrict_mode": True, "ports": []}))
        code, out, err = self.verify()  # management answers although the policy denies it
        self.assertEqual((code, json.loads(out)["verdict"]), (1, "open"))

    def test_exit_codes_1_means_only_open_3_means_hold_4_means_refused_and_never_undo(self):
        stale = datetime.now(timezone.utc) + timedelta(hours=2)
        code, out, err = self.run_cli(["verify", *self.verify_args(expect="restricted")], now=stale)  # stale receipt: refused
        self.assertEqual((code, out), (4, ""))
        self.assertIn("never undo", err)
        self.assertEqual(self.http.probes, [])
        code, out, err = self.verify()  # correctly restricted, no accepted signature yet
        self.assertEqual((code, json.loads(out)["verdict"]), (3, "not_proven_closed"))
        self.http = FakeHttp(restricted=False)  # open gateway
        code, out, err = self.verify()
        self.assertEqual((code, json.loads(out)["verdict"]), (1, "open"))
        self.assertIn("never undo", json.loads(out)["exit_codes"]["4"])
        self.assertIn("never undo on exit 4", self.applied["after_verify"]["exit 4"])
        self.assertNotIn("undo --snapshot", self.applied["after_verify"]["exit 4"])

    def real_cli(self, *argv):
        return subprocess.run([sys.executable, str(SCRIPT), *argv], text=True, capture_output=True,
                              env={"PATH": "/usr/bin:/bin"})

    def test_the_real_cli_exits_4_not_1_for_a_stale_receipt(self):
        # M5: the default max age is 3600 s and the restart time is unmeasured, so a stale receipt is likely.
        receipt = json.loads(self.receipt.read_text())
        receipt["verified_at_utc"] = (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()
        self.save(self.receipt, receipt)
        result = self.real_cli("verify", *self.verify_args(expect="restricted"))
        self.assertEqual(result.returncode, 4)
        self.assertEqual(result.stdout, "")
        self.assertIn("Refused", result.stderr)
        self.assertIn("stale", result.stderr)
        self.assertIn("never undo", result.stderr)

    def test_cli_maps_every_unexpected_error_to_4_and_leaves_argparse_at_2(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), mock.patch.object(cf_only, "main", side_effect=RuntimeError("boom-detail")):
            self.assertEqual(cf_only.cli([]), 4)
        self.assertNotIn("boom-detail", err.getvalue())
        self.assertIn("do NOT treat this as closed", err.getvalue())
        self.assertIn("do NOT undo on this alone", err.getvalue())
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            cf_only.cli(["verify"])
        self.assertEqual(raised.exception.code, 2)
        garbage = self.root / "receipt-garbage.json"
        garbage.write_text("not json")
        garbage.chmod(0o600)
        result = self.real_cli("verify", *self.verify_args(expect="restricted", receipt=garbage))
        self.assertEqual((result.returncode, result.stdout), (4, ""))

    def test_a_2xx_from_a_restricted_path_is_open_but_other_statuses_stay_not_proven_closed(self):
        for outcome, expected in (("http_200_unparsed", (1, "open")), ("http_204", (1, "open")),
                                  ("http_404", (3, "not_proven_closed")), ("http_502", (3, "not_proven_closed")),
                                  ("http_301", (3, "not_proven_closed")), ("tls_rejected", (3, "not_proven_closed")),
                                  ("closed_after_tls", (3, "not_proven_closed"))):
            with self.subTest(outcome):
                self.http = FakeHttp()
                self.http.probe_map[(f"{APP}-8000.{GATEWAY}", "ipv4")] = {"outcome": outcome}
                code, out, err = self.verify()
                self.assertEqual((code, json.loads(out)["verdict"]), expected, out)

    def test_next_action_text_is_per_mode_and_a_vantage_transport_failure_asks_for_a_second_network(self):
        # restored: exit 1 = the node path is broken after the restore: investigate, never "undo" again
        self.http = FakeHttp(restricted=False)
        self.http.probe_map[(cf_only.TEE_HOST, "ipv4")] = {"outcome": "tcp_refused"}
        code, out, err = self.verify(expect="restored")
        result = json.loads(out)
        self.assertEqual((code, result["verdict"]), (1, "open"))
        self.assertIn("Do NOT undo again", result["next_action"])
        self.assertIn("do NOT undo again", result["exit_codes"]["1"])
        self.assertNotIn("drill", result["next_action"])
        self.assertIsNone(result["blocked"])
        # restored from a v4-only vantage with a management AAAA: exit 3, re-run from an IPv6-capable network
        self.http = FakeHttp(restricted=False)
        self.http.mgmt6 = {"outcome": "no_route"}
        code, out, err = self.verify(expect="restored")
        result = json.loads(out)
        self.assertEqual((code, result["verdict"]), (3, "not_proven_closed"))
        self.assertIn("second IPv6-capable network", result["next_action"])
        self.assertIn("Do NOT undo again", result["next_action"])
        self.assertNotIn("run the drill", result["next_action"])
        # restricted exit 3 names the concrete check; restricted exit 1 from a /info transport failure asks to confirm
        self.http = FakeHttp()
        code, out, err = self.verify()
        self.assertIn("SECOND, IPv6-capable network", json.loads(out)["next_action"])
        self.assertIn("tee.node.tinycloud.xyz /info", json.loads(out)["next_action"])
        self.http = FakeHttp()
        self.http.info_map["node.tinycloud.xyz"] = {"status": None, "node_id": None}
        code, out, err = self.verify()
        result = json.loads(out)
        self.assertEqual((code, result["verdict"]), (1, "open"))
        self.assertIn("confirm from a second network before undo", result["next_action"])
        self.http = FakeHttp()
        self.http.info_map["node.tinycloud.xyz"] = {"status": 502, "node_id": None}  # an HTTP answer: no such hedge
        self.assertNotIn("second network before undo", json.loads(self.verify()[1])["next_action"])

    def test_management_refused_or_reset_at_connect_is_pre_sni_and_exit_3_but_post_accept_failures_are_open(self):
        # M6: same gateway IP:443, so a connect-time refusal/reset cannot be about this app (M1 gateway-wide outage, M2 mgmt
        # refused, B local REJECT), even with a CORRECT restriction in place. Post-accept failures stay open.
        for family in ("ipv4", "ipv6"):
            for outcome in ("tcp_refused", "tcp_reset"):
                with self.subTest(family=family, outcome=outcome):
                    self.http = FakeHttp()
                    setattr(self.http, "mgmt" if family == "ipv4" else "mgmt6", {"outcome": outcome})
                    code, out, err = self.verify()
                    self.assertEqual((code, json.loads(out)["verdict"]), (3, "not_proven_closed"), out)
            for outcome in ("reset_after_connect", "tls_rejected", "closed_after_tls", "non_ssh_data", "malformed_http",
                            "http_200_unparsed", "http_502"):
                with self.subTest(family=family, outcome=outcome):
                    self.http = FakeHttp()
                    setattr(self.http, "mgmt" if family == "ipv4" else "mgmt6", {"outcome": outcome})
                    code, out, err = self.verify()
                    self.assertEqual((code, json.loads(out)["verdict"]), (1, "open"), out)
        # whole gateway down (M1): every probe and management refused, correct restriction: still hold, not undo
        self.http = FakeHttp()
        self.http.mgmt = self.http.mgmt6 = {"outcome": "tcp_refused"}
        code, out, err = self.verify()
        self.assertEqual(code, 3, out)
        self.assertIn("SSH-2.0 banner", json.loads(out)["next_action"])  # the exit-3 checklist names the management check

    def test_a_receipt_write_failure_never_turns_a_verdict_into_exit_4(self):
        # S10: record_verify runs before emit; a leftover .record, a full disk or bad permissions must not mask OPEN.
        leftover = self.receipt.with_name(self.receipt.name + ".record")
        leftover.write_text("{}")
        for restricted, expected in ((False, (1, "open")), (True, (3, "not_proven_closed"))):
            with self.subTest(restricted=restricted):
                self.http = FakeHttp(restricted=restricted)
                before = self.receipt.read_text()
                code, out, err = self.verify()
                result = json.loads(out)
                self.assertEqual((code, result["verdict"]), expected, out)
                self.assertTrue(result["receipt_record"].startswith("FAILED"), result["receipt_record"])
                self.assertIn("Warning", err)
                self.assertEqual(self.receipt.read_text(), before)
        leftover.unlink()
        self.http = FakeHttp(restricted=False)
        with mock.patch.object(cf_only, "record_verify", side_effect=OSError("disk-full-detail")):
            code, out, err = self.verify()
        self.assertEqual((code, json.loads(out)["verdict"]), (1, "open"))
        self.assertNotIn("disk-full-detail", err + out)

    def closed_checks(self, out):
        return [c for c in json.loads(out)["checks"] if "accepted closed signature" in c["check"]]

    def test_the_shipped_set_is_empty_and_the_cli_cannot_widen_it(self):
        self.assertEqual(cf_only.ACCEPTED_CLOSED_SIGNALS, ())
        for flag in ("--accept-closed-signal", "--closed-signal"):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                self.verify(flag, "tcp_refused")

    def test_a_refusal_or_reset_alone_fails_and_says_a_drill_is_required(self):
        hosts = cf_only.direct_hosts(mock.Mock(expect_app_id=APP, instance_id=INSTANCE, gateway_domain=GATEWAY,
                                               extra_host=None))
        for signal in ("tcp_refused", "tcp_reset"):
            with self.subTest(signal):
                self.http = FakeHttp()
                self.http.probe_map = {(h, f): {"outcome": signal} for h in hosts for f in ("ipv4", "ipv6")}
                code, out, err = self.verify()
                result = json.loads(out)
                self.assertEqual((code, result["result"], result["verdict"]), (3, "FAIL", "not_proven_closed"), out)
                self.assertEqual(result["blocked"], "no accepted closed signature yet: drill required")
                self.assertEqual(result["accepted_closed_signals"], [])
                closed = self.closed_checks(out)
                self.assertEqual(len(closed), 2 * len(hosts))
                self.assertTrue(all(c["status"] == "fail" and "drill required" in c["detail"] for c in closed))
                self.assertEqual(self.http.control_calls, [])  # nothing accepted, so no control can rescue a refusal

    def test_an_open_gateway_fails_and_the_aaaa_waiver_cannot_rescue_ipv4(self):
        self.http = FakeHttp(restricted=False)
        code, out, err = self.verify()
        self.assertEqual(code, 1, out)
        self.assertFalse([c for c in self.closed_checks(out) if c["status"] == "pass"])
        self.http = FakeHttp()
        self.http.probe_map = {(h, "ipv6"): {"outcome": "no_aaaa"} for h in (cf_only.TEE_HOST, f"{APP}-443s.{GATEWAY}")}
        self.assertEqual(self.verify("--allow-no-aaaa")[0], 3)

    def test_an_instance_id_typo_cannot_pass(self):
        self.http = FakeHttp()
        self.http.instance_mgmt = {"outcome": "tcp_refused"}
        code, out, err = self.verify()
        self.assertEqual(code, 3, out)
        failed = [c["check"] for c in json.loads(out)["checks"] if c["status"] != "pass"]
        self.assertTrue(any("--instance-id is a real gateway host" in c for c in failed), failed)

    def test_the_block_applies_to_restricted_only_and_every_failed_run_is_recorded_with_its_addresses(self):
        code, out, err = self.verify()
        self.assertEqual(code, 3)
        run = json.loads(self.receipt.read_text())["verify_runs"][-1]
        self.assertEqual((run["result"], run["accepted_closed_signals"]), ("FAIL", []))
        recorded = [c for c in run["checks"] if "accepted closed signature" in c["check"]]
        self.assertTrue(recorded and all(c["addresses"] in ([ADDR["ipv4"]], [ADDR["ipv6"]]) for c in recorded))
        self.http = FakeHttp(restricted=False)
        code, out, err = self.verify(expect="restored")
        self.assertEqual(code, 0, out)
        self.assertIsNone(json.loads(out)["blocked"])


class UndoTest(Base):
    def setUp(self):
        super().setUp()
        self.run_cli(["preflight", *self.cloudflare_args(), "--out", str(self.receipt)])
        self.stage()
        self.undo_patch = self.root / "undo.patch.json"

    def undo(self, *extra, **overrides):
        argv = ["undo", "--compose", str(self.compose), "--target", str(self.target),
                "--patch-out", str(self.undo_patch), *self.verify_args(expect="restored")[2:], *extra]
        for flag, value in overrides.items():
            argv[argv.index(flag) + 1] = value
        return self.run_cli(argv)

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
        self.assertIn(f"--receipt {self.receipt}", result["then_verify"])
        self.assertNotIn("RECEIPT.json", result["then_verify"])
        self.assertIn("HTTP first", " ".join(result["order"]))
        self.assertEqual(self.compose.read_bytes(), staged)

    def test_printed_verify_command_quotes_values_and_rejects_unvalidated_ones(self):
        for flag, value in (("--instance-id", "x; rm -rf /"), ("--instance-id", "<$(id)>"),
                            ("--gateway-domain", "gw.example.test; id"), ("--gateway-domain", "<gw>"),
                            ("--tunnel-host", "$(id).example.test"), ("--tunnel-host", "node.tinycloud.xyz")):
            with self.subTest(flag=flag, value=value):
                self.undo_patch.unlink(missing_ok=True)
                code, out, err = self.undo(**{flag: value})
                self.assertEqual(code, 4, out)
                self.assertFalse(self.undo_patch.exists())
        self.undo_patch.unlink(missing_ok=True)
        self.receipt.chmod(0o644)
        self.assertEqual(self.undo()[0], 4)

    def test_apply_stages_local_restore_and_refuses_drift_and_loose_snapshot(self):
        current = json.loads(self.compose.read_text())
        current["port_policy"] = {"restrict_mode": False, "ports": []}
        self.save(self.compose, current)
        self.assertEqual(self.undo("--apply")[0], 4)
        self.assertFalse(self.undo_patch.exists())
        current["port_policy"] = json.loads(self.snapshot.read_text())["after"]
        self.save(self.compose, current)
        self.snapshot.chmod(0o644)
        self.assertEqual(self.undo("--apply")[0], 4)
        self.snapshot.chmod(0o600)
        code, out, err = self.undo("--apply")
        self.assertEqual(code, 0, err)
        self.assertIsNone(json.loads(self.compose.read_text())["port_policy"])

    def test_refuses_to_overwrite_an_existing_patch_file(self):
        self.undo_patch.write_text("{}")
        self.assertEqual(self.undo()[0], 4)
        self.assertEqual(self.undo_patch.read_text(), "{}")


class UndoAbsentPolicyTest(Base):
    def test_an_originally_absent_policy_is_removed_again_not_nulled(self):
        original = {k: v for k, v in self.original.items() if k != "port_policy"}
        self.save(self.compose, original)
        self.run_cli(["preflight", *self.cloudflare_args(), "--out", str(self.receipt)])
        self.stage()
        self.assertIn("port_policy", json.loads(self.compose.read_text()))
        patch = self.root / "undo.json"
        code, out, err = self.run_cli(["undo", "--compose", str(self.compose), "--target", str(self.target),
                                       "--patch-out", str(patch), *self.verify_args(expect="restored")[2:], "--apply"])
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["payload"], {"compose": {"port_policy": None}})
        self.assertEqual(json.loads(self.compose.read_text()), original)


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
        for secret in (SECRET, NODE):
            self.assertNotIn(secret, text)
        self.assertIn(cf_only.fingerprint(NODE), text)

    def test_cli_refuses_without_a_cloudflare_read_token_before_any_network(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "preflight", *self.cloudflare_args()], text=True,
                                capture_output=True, env={"PATH": "/usr/bin:/bin"})
        self.assertEqual(result.returncode, 4)
        self.assertIn("CLOUDFLARE_READ_TOKEN", result.stderr)
        self.assertEqual(result.stdout, "")


class Reply(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def cf_reply(result):
    return Reply(json.dumps({"success": True, "result": result}).encode())


class CloudflareReaderTest(unittest.TestCase):
    def make(self, bindings, versions=None, seen=None, deployments=None):
        versions = versions if versions is not None else [{"version_id": "v9", "percentage": 100}]
        deployments = deployments or [{"created_on": "2026-01-02", "versions": versions}]

        def opener(request, timeout):
            url = request.full_url
            if seen is not None:
                seen.append((request.get_method(), url, request.get_header("Authorization")))
            self.assertNotIn("/content", url)  # the Worker source is never read
            self.assertFalse(url.endswith("/settings"))  # script-level settings are not version-bound
            if "/versions/" in url:
                return cf_reply({"resources": {"bindings": bindings}})
            if url.endswith("/deployments"):
                return cf_reply({"deployments": deployments})
            if "workers/routes" in url:
                return cf_reply([{"pattern": "node.tinycloud.xyz/*", "script": "s", "id": "ignored"}])
            return cf_reply({"id": TUNNEL})
        return cf_only.CloudflareReader(CF_TOKEN, ACCT, ZONE, opener=opener)

    def test_is_get_only_binds_the_binding_to_the_deployed_version_and_never_leaks_its_token(self):
        seen = []
        reader = self.make([{"name": "ORIGIN_URL", "type": "secret_text"}], seen=seen)
        self.assertEqual(reader.worker("s"), {"version_id": "v9", "origin_binding": "secret_text",
                                              "routes": [{"pattern": "node.tinycloud.xyz/*", "script": "s"}]})
        self.assertEqual(reader.tunnel(TUNNEL), {"id": TUNNEL})
        self.assertTrue(any(f"/scripts/s/versions/v9" in u for m, u, a in seen))
        self.assertTrue(seen and all(m == "GET" and a == f"Bearer {CF_TOKEN}" for m, u, a in seen))
        for failure in (HTTPError("u", 403, "denied " + CF_TOKEN, {}, None), URLError("boom " + CF_TOKEN)):
            def failing(request, timeout, failure=failure):
                raise failure
            with self.assertRaises(cf_only.ClientError) as caught:
                cf_only.CloudflareReader(CF_TOKEN, ACCT, ZONE, opener=failing).tunnel(TUNNEL)
            self.assertNotIn(CF_TOKEN, str(caught.exception))

    def test_the_newest_deployment_wins_and_a_split_rollout_has_no_version(self):
        seen = []
        reader = self.make([{"name": "ORIGIN_URL", "type": "secret_text"}], seen=seen, deployments=[
            {"created_on": "2026-01-01", "versions": [{"version_id": "old", "percentage": 100}]},
            {"created_on": "2026-01-03", "versions": [{"version_id": "new", "percentage": 100}]},
            {"created_on": "2026-01-02", "versions": [{"version_id": "mid", "percentage": 100}]}])
        self.assertEqual(reader.worker("s")["version_id"], "new")
        split = self.make([{"name": "ORIGIN_URL", "type": "secret_text"}], versions=[
            {"version_id": "a", "percentage": 50}, {"version_id": "b", "percentage": 50}])
        result = split.worker("s")
        self.assertEqual((result["version_id"], result["origin_binding"]), (None, None))
        injected = self.make([{"name": "ORIGIN_URL", "type": "secret_text"}], versions=[
            {"version_id": "../../x", "percentage": 100}])
        self.assertEqual(injected.worker("s")["origin_binding"], None)

    def test_origin_binding_is_read_by_name_and_type_only(self):
        var = {"name": "ORIGIN_URL", "type": "secret_text"}
        self.assertEqual(self.make([{"name": "OTHER", "type": "plain_text", "text": "x"}, var]).worker("s")["origin_binding"],
                         "secret_text")
        self.assertEqual(self.make([dict(var, type="plain_text", text="https://x.example.test")]).worker("s")["origin_binding"],
                         "plain_text")
        for name, bindings in {"absent": [], "other name only": [dict(var, name="PHALA_ORIGIN")],
                               "duplicated": [var, dict(var, type="plain_text")], "no type": [{"name": "ORIGIN_URL"}]}.items():
            with self.subTest(name):
                self.assertIsNone(self.make(bindings).worker("s")["origin_binding"])

    def test_ids_are_validated_before_they_reach_a_url_path(self):
        for account, zone in (("acct", ZONE), (ACCT, "zone"), (ACCT + "/x", ZONE), (ACCT, ZONE[:-1] + "?")):
            with self.subTest(account=account, zone=zone), self.assertRaises(cf_only.Refusal):
                cf_only.CloudflareReader(CF_TOKEN, account, zone)
        for script in ("a/b", "../x", "", "a b", "x" * 80):
            with self.subTest(script=script), self.assertRaises(cf_only.Refusal):
                self.make([]).worker(script)


# ---------------------------------------------------------------- probe classifier, localhost only

@unittest.skipUnless(shutil.which("openssl"), "openssl is needed to generate a throwaway localhost certificate")
class ProbeClassifierTest(unittest.TestCase):
    """The real NetworkProbe against a loopback TLS server: no external network."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.cert, cls.key = f"{cls.tmp.name}/cert.pem", f"{cls.tmp.name}/key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", cls.key, "-out", cls.cert,
                        "-days", "1", "-subj", "/CN=localhost"], check=True, capture_output=True)
        cls.probe = cf_only.NetworkProbe(timeout=0.7)

    def serve(self, behavior):
        """behavior(conn_after_handshake) for TLS behaviours, or 'alert' / 'silent' for pre-handshake ones."""
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        stop = threading.Event()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)

        def loop():
            listener.settimeout(0.2)
            while not stop.is_set():
                try:
                    conn, _ = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                with conn:
                    conn.settimeout(2)
                    try:
                        if behavior == "alert":
                            conn.recv(1024)
                            conn.sendall(bytes([21, 3, 3, 0, 2, 2, 40]))  # fatal handshake_failure alert
                        elif behavior == "silent":
                            stop.wait(1.5)
                        else:
                            with context.wrap_socket(conn, server_side=True) as tls:
                                behavior(tls)
                    except (OSError, ssl.SSLError):
                        pass

        thread = threading.Thread(target=loop, daemon=True)
        thread.start()
        self.addCleanup(lambda: (stop.set(), listener.close(), thread.join(2)))
        return listener.getsockname()[1]

    @staticmethod
    def respond(status, body=b"", headers=(), chunked=False):
        def handler(tls):
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = tls.recv(4096)
                if not chunk:
                    return
                data += chunk
            head = [f"HTTP/1.1 {status} X", "Connection: close", *headers]
            if chunked:
                head.append("Transfer-Encoding: chunked")
                half = len(body) // 2
                payload = b"".join(b"%x\r\n%s\r\n" % (len(p), p) for p in (body[:half], body[half:]) if p) + b"0\r\n\r\n"
            else:
                head.append(f"Content-Length: {len(body)}")
                payload = body
            tls.sendall(("\r\n".join(head) + "\r\n\r\n").encode() + payload)
        return handler

    def result(self, port, banner=False):
        if banner:
            return self.probe.mgmt_probe("localhost", "ipv4", port)
        return self.probe.probe("localhost", "ipv4", port)

    INFO = json.dumps({"nodeId": NODE, "version": "x"}).encode()

    def test_content_length_200_with_a_node_id_is_node_info(self):
        port = self.serve(self.respond(200, self.INFO))
        self.assertEqual(self.result(port), {"outcome": "node_info", "signals": ["node_info"], "node_id": NODE,
                                              "addresses": ["127.0.0.1"]})

    def test_a_chunked_200_with_a_node_id_is_node_info_not_closed(self):
        port = self.serve(self.respond(200, self.INFO, chunked=True))
        result = self.result(port)
        self.assertEqual((result["outcome"], result.get("node_id")), ("node_info", NODE))
        self.assertEqual(cf_only.judge_closed(result)[0], "fail")

    def test_anything_that_completes_http_or_tls_is_open_or_unknown_and_fails(self):
        cases = {"http_404": self.respond(404, b"nope"), "http_502": self.respond(502, b"bad gateway"),
                 "http_421": self.respond(421, b""), "http_200_unparsed": self.respond(200, b"<html>ok</html>"),
                 "http_301": self.respond(301, b"", headers=("Location: https://x.example.test/",)),
                 "closed_after_tls": lambda tls: None}
        for signal, handler in cases.items():
            with self.subTest(signal):
                result = self.result(self.serve(handler))
                self.assertEqual(result["signals"], [signal])
                self.assertEqual(cf_only.judge_closed(result)[0], "fail")

    def test_tls_alert_is_tls_rejected_and_fails(self):
        result = self.result(self.serve("alert"))
        self.assertEqual(result["signals"], ["tls_rejected"])
        self.assertEqual(cf_only.judge_closed(result)[0], "fail")

    def test_silence_is_a_timeout_and_fails(self):
        result = self.result(self.serve("silent"))
        self.assertEqual(result["signals"], ["timeout"])
        self.assertEqual(cf_only.judge_closed(result)[0], "fail")

    def test_a_closed_port_is_tcp_refused_which_is_not_accepted_as_closed_by_default(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        listener.close()
        result = self.result(port)
        self.assertEqual(result["signals"], ["tcp_refused"])
        self.assertEqual(cf_only.judge_closed(result)[0], "fail")  # shipped set is empty: a refusal alone never passes
        with mock.patch.object(cf_only, "ACCEPTED_CLOSED_SIGNALS", ("tcp_refused", "tcp_reset")):  # TEST-ONLY
            self.assertEqual(cf_only.judge_closed(result)[0], "pass")

    def test_probe_records_resolved_addresses_and_control_uses_the_same_exact_address(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        listener.close()
        result = self.result(port)
        self.assertEqual((result["signals"], result["addresses"]), (["tcp_refused"], ["127.0.0.1"]))
        banner_port = self.serve(lambda tls: tls.sendall(b"SSH-2.0-OpenSSH_9.6\r\n"))
        self.assertEqual(self.probe.control("127.0.0.1", "ipv4", "known-open.example.test", port=banner_port), "ssh_banner")
        self.assertEqual(self.probe.control("127.0.0.1", "ipv4", "known-open.example.test", port=port), "tcp_refused")
        self.assertEqual(self.probe.control("127.0.0.1", "ipv4", "x.example.test", port=self.serve("alert")), "tls_rejected")

    def test_unresolvable_name_is_no_address(self):
        self.assertEqual(self.probe.probe("no-such-host.invalid", "ipv4", 443)["signals"], ["no_address"])

    def test_dns_failure_kinds_decide_whether_a_missing_aaaa_is_nodata(self):
        def lookup(v4, v6):
            def fake(host, port, family, kind):
                outcome = v6 if family == socket.AF_INET6 else v4
                if isinstance(outcome, Exception):
                    raise outcome
                return [(family, kind, 6, "", outcome)]
            return fake

        nodata = socket.gaierror(getattr(socket, "EAI_NODATA", socket.EAI_NONAME), "no data")
        nxdomain = socket.gaierror(socket.EAI_NONAME, "unknown")
        again = socket.gaierror(socket.EAI_AGAIN, "temporary failure")
        v4_ok = ("192.0.2.1", 443)
        cases = (("NODATA on a name that resolves over IPv4", lookup(v4_ok, nodata), "no_aaaa"),
                 ("NONAME for AAAA on a name that resolves over IPv4", lookup(v4_ok, nxdomain), "no_aaaa"),
                 ("NXDOMAIN (name does not exist at all)", lookup(nxdomain, nxdomain), "no_address"),
                 ("resolver timeout/error on the AAAA lookup", lookup(v4_ok, again), "no_address"),
                 ("resolver error on both lookups", lookup(again, again), "no_address"))
        for name, fake, signal in cases:
            with self.subTest(name), mock.patch.object(cf_only.socket, "getaddrinfo", fake):
                self.assertEqual(self.probe.probe("x.example.test", "ipv6", 443)["signals"], [signal])
        with mock.patch.object(cf_only.socket, "getaddrinfo", lookup(nodata, nodata)):
            self.assertEqual(self.probe.probe("x.example.test", "ipv4", 443)["signals"], ["no_address"])

    def test_repro_g_an_aaaa_lookup_failure_is_never_waived_by_the_flag(self):
        for code in (socket.EAI_AGAIN, socket.EAI_FAIL, socket.EAI_SYSTEM, socket.EAI_SERVICE):
            def fake(host, port, family, kind, code=code):
                if family == socket.AF_INET6:
                    raise socket.gaierror(code, "resolver failure")
                return [(family, kind, 6, "", ("192.0.2.1", 443))]
            with self.subTest(code), mock.patch.object(cf_only.socket, "getaddrinfo", fake):
                result = self.probe.probe("x.example.test", "ipv6", 443)
                self.assertEqual(result["signals"], ["no_address"])
                self.assertEqual(cf_only.judge_closed(result, "ipv6", True)[0], "fail")

    def test_repro_e2_a_reset_once_connected_is_not_tcp_reset_and_is_never_closed(self):
        connected = mock.MagicMock()  # create_connection succeeded: the gateway accepted the TCP connection
        for where in ("tls", "http"):
            if where == "tls":
                wrap = mock.patch.object(cf_only.ssl.SSLContext, "wrap_socket", side_effect=ConnectionResetError())
            else:
                stream = mock.MagicMock()
                stream.sendall.side_effect = ConnectionResetError()
                wrap = mock.patch.object(cf_only.ssl.SSLContext, "wrap_socket", return_value=stream)
            with self.subTest(where), mock.patch.object(cf_only.socket, "create_connection", return_value=connected), wrap:
                signal = self.probe._attempt(("192.0.2.1", 443), "x.example.test", False)[0]
            self.assertEqual(signal, "reset_after_connect")
            with mock.patch.object(cf_only, "ACCEPTED_CLOSED_SIGNALS", ("tcp_refused", "tcp_reset")):  # TEST-ONLY
                self.assertEqual(cf_only.judge_closed({"signals": [signal]})[0], "fail")

    def test_reset_is_a_positive_refusal_no_route_and_other_errors_are_not(self):
        import errno
        for failure, signal, verdict in ((ConnectionResetError(errno.ECONNRESET, "reset"), "tcp_reset", "pass"),
                                         (OSError(errno.ENETUNREACH, "no route"), "no_route", "fail"),
                                         (OSError(errno.EHOSTUNREACH, "no route"), "no_route", "fail"),
                                         (OSError(errno.EACCES, "denied"), "error", "fail")):
            with self.subTest(signal), mock.patch.object(cf_only.socket, "create_connection", side_effect=failure):
                result = self.probe._attempt(("127.0.0.1", 443), "x.example.test", False)
                self.assertEqual(result[0], signal)
                for family in ("ipv4", "ipv6"):
                    with mock.patch.object(cf_only, "ACCEPTED_CLOSED_SIGNALS", ("tcp_refused", "tcp_reset")):  # TEST-ONLY
                        self.assertEqual(cf_only.judge_closed({"signals": [result[0]]}, family, True)[0], verdict)

    def test_management_banner_is_read_after_the_tls_handshake(self):
        port = self.serve(lambda tls: tls.sendall(b"SSH-2.0-OpenSSH_9.6\r\n"))
        self.assertEqual(self.result(port, banner=True)["signals"], ["ssh_banner"])
        port = self.serve(lambda tls: tls.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n"))
        self.assertEqual(self.result(port, banner=True)["signals"], ["non_ssh_data"])
        self.assertEqual(self.result(self.serve(lambda tls: None), banner=True)["signals"], ["closed_after_tls"])
        self.assertEqual(cf_only.judge_management({"signals": ["non_ssh_data"]}, True)[0], "fail")
        self.assertEqual(cf_only.judge_management({"signals": ["ssh_banner"]}, True)[0], "pass")
        self.assertEqual(cf_only.judge_management({"signals": ["tcp_refused"]}, False)[0], "fail")  # not corroborable
        self.assertEqual(cf_only.judge_management({"signals": ["tls_rejected"]}, False)[0], "fail")
        self.assertEqual(cf_only.judge_management({"signals": ["ssh_banner"]}, False)[0], "fail")


if __name__ == "__main__":
    unittest.main()
