#!/usr/bin/env python3
"""TC-4194 P1: the cloudflared connector's sealed credential and compose shape.

Runs the real "Deploy to Phala Cloud" workflow Bash through the offline harness of
test-deploy-recovery.py (no network, no Docker), adding only the new optional secret.
"""
import importlib.util
import copy
from pathlib import Path
import re
import subprocess
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("deploy_recovery", ROOT / "scripts/ci/test-deploy-recovery.py")
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)

TOKEN = "tc4194-synthetic-tunnel-token"
COMPOSE = (ROOT / "docker-compose.dstack-postgres.yaml").read_text()


def deploy(value):
    """One offline deploy of the reviewed N0 compose; value None leaves the secret unset."""
    harness = recovery.RecoveryTests("run_deploy")
    real_run = subprocess.run

    def run(*args, **kwargs):
        env = kwargs.get("env")
        if env is not None and value is not None:
            kwargs["env"] = {**env, "PHALA_ENV_CLOUDFLARE_TUNNEL_TOKEN": value}
        return real_run(*args, **kwargs)

    recovery.subprocess.run = run
    try:
        result = harness.run_deploy(recovery.N0)
    finally:
        recovery.subprocess.run = real_run
    return result


def network_violations(compose):
    """What the connector could reach beyond tinycloud:8000. Its tunnel rules are managed in Cloudflare, so only
    network membership bounds it: it must be on cf-edge alone (never `default`, never a network postgres or the
    log shipper uses), and tinycloud must be the only other service on cf-edge."""
    services = compose["services"]
    networks = lambda service: set(service.get("networks") or ["default"])
    connector = services["cloudflared"]
    found = []
    if connector.get("network_mode"):
        found.append("cloudflared sets network_mode")
    if networks(connector) != {"cf-edge"}:
        found.append("cloudflared networks are %s, not only cf-edge" % sorted(networks(connector)))
    members = {name for name, service in services.items() if "cf-edge" in networks(service)}
    if members != {"cloudflared", "tinycloud"}:
        found.append("cf-edge members are %s, not cloudflared and tinycloud" % sorted(members))
    for name, service in services.items():
        if name not in ("cloudflared", "tinycloud") and networks(service) & networks(connector):
            found.append("%s shares a network with cloudflared" % name)
    return found


class CloudflaredConnectorTests(unittest.TestCase):
    def test_unset_or_empty_secret_does_not_block_or_reach_the_sealed_env(self):
        for value in (None, ""):
            with self.subTest(value=value):
                result = deploy(value)
                self.assertTrue(result["success"], "A deploy without the tunnel must still work")
                self.assertNotIn("CLOUDFLARE_TUNNEL_TOKEN", result["env_names"])

    def test_set_secret_is_sealed_once_and_never_logged(self):
        result = deploy(TOKEN)
        self.assertTrue(result["success"])
        self.assertEqual(result["env_names"].count("CLOUDFLARE_TUNNEL_TOKEN"), 1)
        self.assertNotIn(TOKEN, result["logs"] + result["summary"])

    def test_multiline_secret_is_refused_before_any_mutation(self):
        result = deploy(TOKEN + "\nextra")
        self.assertFalse(result["success"])
        self.assertNotIn("cvm-deploy", result["events"])

    def test_connector_has_no_published_port_and_a_digest_pin(self):
        service = re.search(r"(?ms)^  cloudflared:\n(.*?)(?=^  \S|^\S|\Z)", COMPOSE)
        self.assertIsNotNone(service, "cloudflared service missing")
        body = service[1]
        self.assertNotRegex(body, r"(?m)^    (ports|expose|network_mode|privileged):")
        self.assertRegex(body, r"(?m)^    image: cloudflare/cloudflared:[0-9.]+@sha256:[0-9a-f]{64}$")
        self.assertIn('TUNNEL_TOKEN: "${CLOUDFLARE_TUNNEL_TOKEN:-}"', body)

    def test_connector_network_scope_is_cf_edge_with_tinycloud_only(self):
        compose = yaml.safe_load(COMPOSE)
        self.assertEqual(network_violations(compose), [])
        self.assertIn("cf-edge", compose["networks"])

    def test_network_check_rejects_widened_scope(self):
        # Each mutation widens what the remotely managed tunnel could reach; the check must name it.
        def mutated(change):
            compose = copy.deepcopy(yaml.safe_load(COMPOSE))
            change(compose["services"])
            return network_violations(compose)

        cases = {
            "default network": lambda s: s["cloudflared"].update(networks=["cf-edge", "default"]),
            "implicit default network": lambda s: s["cloudflared"].pop("networks"),
            "log shipper network": lambda s: s["cloudflared"]["networks"].append("logship"),
            "unlisted network": lambda s: s["cloudflared"]["networks"].append("extra"),
            "host network": lambda s: s["cloudflared"].update(network_mode="host"),
            "ingress joins cf-edge": lambda s: s["dstack-ingress"].update(networks=["default", "cf-edge"]),
            "vector joins cf-edge": lambda s: s["vector"]["networks"].append("cf-edge"),
            "tinycloud leaves cf-edge": lambda s: s["tinycloud"].update(networks=["default"]),
        }
        for name, change in cases.items():
            with self.subTest(name):
                self.assertNotEqual(mutated(change), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
