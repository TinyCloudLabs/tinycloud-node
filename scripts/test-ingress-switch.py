#!/usr/bin/env python3
"""Isolated CLI contracts; the HTTP exercise models Phala policy, not Phala itself."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import urlopen

SCRIPT = Path(__file__).with_name("ingress-switch.py")
APP = "a" * 40
TUNNEL = "11111111-2222-4333-8444-555555555555"


class SwitchTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.compose = self.root / "app-compose.json"
        self.target = self.root / "target.json"
        self.network = self.root / "network.json"
        self.proof = self.root / "verified-origin.json"
        self.snapshot = self.root / "previous.json"
        self.original = {"gateway_enabled": True, "docker_compose_file": "unchanged: secret-marker",
                         "requirements": {"health_check": True}, "port_policy": None}
        self.save(self.compose, self.original)
        self.save(self.target, {"id": "cvm_local", "app_id": APP})
        self.save(self.network, {"cvm_id": "cvm_local", "is_online": True, "error": None,
                                "ingress": {"gateway_enabled": True, "port_policy": None},
                                "port_mappings": []})
        self.receipt = {"app_id": APP, "public_url": "https://node.tinycloud.xyz",
                        "worker_origin": "https://cf-origin.example.test",
                        "tunnel_hostname": "cf-origin.example.test", "tunnel_id": TUNNEL,
                        "verified_at_utc": datetime.now(timezone.utc).isoformat(),
                        "connector_authenticated": True,
                        "origin_status": 200, "public_status": 200,
                        "origin_node_id": "did:key:local-node", "public_node_id": "did:key:local-node"}
        self.save(self.proof, self.receipt)

    def save(self, path, value):
        path.write_text(json.dumps(value))
        path.chmod(0o600)

    def run_switch(self, *extra):
        return subprocess.run([sys.executable, str(SCRIPT), "--compose", str(self.compose),
                               "--target", str(self.target), "--expect-app-id", APP,
                               *extra], text=True, capture_output=True)

    def close(self, *extra):
        return self.run_switch("--network", str(self.network), "--verified-origin", str(self.proof),
                               "--snapshot", str(self.snapshot), *extra)

    def test_default_dry_run_does_not_write(self):
        before = self.compose.read_bytes()
        result = self.close()
        self.assertEqual(result.returncode, 0, result.stderr)
        plan = json.loads(result.stdout)
        self.assertFalse(plan["applied_local"])
        self.assertEqual(plan["patch"], {"compose": {"port_policy": {
            "restrict_mode": True, "ports": [{"port": 10022, "pp": False}]}}})
        self.assertEqual(self.compose.read_bytes(), before)
        self.assertFalse(self.snapshot.exists())
        self.assertNotIn("secret-marker", result.stdout + result.stderr)

    def test_restore_exact_policy_preserves_unrelated_changes(self):
        for previous in [None, {"restrict_mode": False, "ports": [{"port": 443, "pp": True}]}]:
            with self.subTest(previous=previous):
                self.snapshot.unlink(missing_ok=True)
                original = dict(self.original, port_policy=previous)
                self.save(self.compose, original)
                network = json.loads(self.network.read_text())
                network["ingress"]["port_policy"] = previous
                self.save(self.network, network)
                result = self.close("--apply")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.snapshot.stat().st_mode & 0o777, 0o600)
                current = json.loads(self.compose.read_text())
                current["unrelated_new_setting"] = 7
                self.save(self.compose, current)
                restored = self.run_switch("--restore", str(self.snapshot), "--apply")
                self.assertEqual(restored.returncode, 0, restored.stderr)
                self.assertEqual(json.loads(self.compose.read_text()), dict(original, unrelated_new_setting=7))
                self.assertEqual(json.loads(restored.stdout)["patch"], {"compose": {"port_policy": previous}})

    def test_restore_absent_policy_and_reject_drift(self):
        original = copy.deepcopy(self.original)
        del original["port_policy"]
        self.save(self.compose, original)
        result = self.close("--apply")
        self.assertEqual(result.returncode, 0, result.stderr)
        current = json.loads(self.compose.read_text())
        current["port_policy"]["ports"].append({"port": 443})
        self.save(self.compose, current)
        rejected = self.run_switch("--restore", str(self.snapshot), "--apply")
        self.assertNotEqual(rejected.returncode, 0)
        self.assertEqual(json.loads(self.compose.read_text()), current)
        current["port_policy"]["ports"].pop()
        self.save(self.compose, current)
        restored = self.run_switch("--restore", str(self.snapshot), "--apply")
        self.assertEqual(restored.returncode, 0, restored.stderr)
        self.assertEqual(json.loads(self.compose.read_text()), original)
        self.assertIsNone(json.loads(restored.stdout)["patch"]["compose"]["port_policy"])

    def test_unknown_or_dependent_routing_never_changes_config(self):
        invalid = [dict(self.receipt, worker_origin="https://app-8000.phala.network"),
                   dict(self.receipt, connector_authenticated=False),
                   dict(self.receipt, public_node_id="did:key:another-node"),
                   dict(self.receipt, public_status=502), dict(self.receipt, app_id="b" * 40)]
        before = self.compose.read_bytes()
        for receipt in invalid:
            with self.subTest(receipt=receipt):
                self.save(self.proof, receipt)
                result = self.close("--apply")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.compose.read_bytes(), before)
                self.assertFalse(self.snapshot.exists())
        self.proof.unlink()
        self.assertNotEqual(self.close("--apply").returncode, 0)

    def test_direct_host_mapping_or_unknown_gateway_state_refused(self):
        for changes in [{"port_mappings": [{"vm_port": 8000}]}, {"is_online": False},
                        {"ingress": None}, {"error": "unknown secret-marker"}]:
            with self.subTest(changes=changes):
                network = {"cvm_id": "cvm_local", "is_online": True, "error": None, "ingress": {
                    "gateway_enabled": True, "port_policy": None}, "port_mappings": []}
                self.save(self.network, dict(network, **changes))
                before = self.compose.read_bytes()
                result = self.close("--apply")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.compose.read_bytes(), before)
                self.assertNotIn("secret-marker", result.stdout + result.stderr)
                self.assertFalse(self.snapshot.exists())

    def test_local_fake_origin_keeps_tunnel_and_management(self):
        compose = self.compose

        class Origin(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"local-node")

            def log_message(self, *args):
                pass

        origin = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
        origin_url = f"http://127.0.0.1:{origin.server_port}"

        class Gateway(Origin):
            def do_GET(self):
                port = {"/tee/info": 443, "/app-8000/info": 8000,
                        "/instance-8000/info": 8000, "/management": 10022}.get(self.path)
                policy = json.loads(compose.read_text()).get("port_policy") or {}
                allowed = {p["port"] for p in policy.get("ports", [])}
                if port and policy.get("restrict_mode") and port not in allowed:
                    self.send_error(403)
                    return
                with urlopen(origin_url + "/info") as response:
                    body = response.read()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(body)

        gateway = ThreadingHTTPServer(("127.0.0.1", 0), Gateway)
        for server in (origin, gateway):
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
        url = f"http://127.0.0.1:{gateway.server_port}"
        paths = ["/tee/info", "/app-8000/info", "/instance-8000/info"]
        for path in paths:
            with urlopen(url + path) as response:
                self.assertEqual(response.read(), b"local-node")
        result = self.close("--apply")
        self.assertEqual(result.returncode, 0, result.stderr)
        for path in paths:
            with self.assertRaises(HTTPError) as denied:
                urlopen(url + path)
            self.assertEqual(denied.exception.code, 403)
        for path in ["/tunnel/info", "/management"]:
            with urlopen(url + path) as response:
                self.assertEqual(response.read(), b"local-node")
        restored = self.run_switch("--restore", str(self.snapshot), "--apply")
        self.assertEqual(restored.returncode, 0, restored.stderr)
        for path in paths:
            with urlopen(url + path) as response:
                self.assertEqual(response.read(), b"local-node")
        print("LOCAL FAKE ORIGIN: tee/app/instance denied; tunnel+management healthy; undo restored (modeled gateway)")


if __name__ == "__main__":
    unittest.main()
