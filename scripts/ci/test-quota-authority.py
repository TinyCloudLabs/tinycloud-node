#!/usr/bin/env python3
"""Synthetic HTTP contracts for reviewed node/billing quota authority."""
import contextlib
import gzip
import http.client
import io
import json
from pathlib import Path
import random
import secrets
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/reconcile-quota.py"
NS = {"__name__": "quota_authority_test", "__file__": str(SCRIPT)}
exec(compile(SCRIPT.read_text(), str(SCRIPT), "exec"), NS)

OWNER = "tinycloud:pkh:eip155:1:0xd559CCd9EB87c530A9a349262669386dE93cf412"
LIMITS = {OWNER + ":applications": 5368709120, OWNER + ":secrets": 268721121}
CANARIES = []
USAGE_CAP = 16 * 1024 * 1024


def realistic_inventory(total):
    """The node's real GET /admin/usage body (routes/admin.rs `UsageResponse`):
    every space on the node, unpaginated, as compact serde JSON with `spaces`
    before `count`, sorted by usage descending with unknown (null) last.
    Production held about 1,034 spaces on 2026-10-12 (~107 bytes a row)."""
    rng = random.Random(959)
    rows = [{"space_id": space, "usage_bytes": usage}
            for space, usage in zip(LIMITS, (640743590, 1048576))]
    while len(rows) < total:
        owner = "tinycloud:pkh:eip155:1:0x" + "".join(rng.choice("0123456789abcdef") for _ in range(40))
        name = rng.choice(("default", "applications", "secrets", "kv", "public", "notes"))
        rows.append({"space_id": owner + ":" + name,
                     "usage_bytes": None if rng.random() < 0.4 else rng.randint(1, 700_000_000)})
    rows.sort(key=lambda row: (row["usage_bytes"] is None, -(row["usage_bytes"] or 0)))
    return json.dumps({"spaces": rows, "count": len(rows)}, separators=(",", ":")).encode()


class SafeResult(unittest.TextTestResult):
    def _exc_info_to_string(self, error, test):
        output = super()._exc_info_to_string(error, test)
        for value in [*CANARIES, *LIMITS]:
            output = output.replace(value, "[withheld]")
        return output


class AuthorityTests(unittest.TestCase):
    def setUp(self):
        self.node_secret = secrets.token_urlsafe(32)
        self.billing_secret = secrets.token_urlsafe(32)
        CANARIES.extend([self.node_secret, self.billing_secret])
        self.ports = []
        self.calls = []
        self.values = {}
        self.billing_status = {space: 404 for space in LIMITS}
        self.billing_body = {space: {"active": False, "comp_bytes": 0,
                                    "account_limit_bytes": 104857600, "storage_limit_bytes": None}
                             for space in LIMITS}
        self.transport_failures = 0
        self.apply_put = True
        self.node_status = 200
        self.bad_effective = False
        self.usage = [{"space_id": space, "usage_bytes": 10} for space in LIMITS]
        self.usage_body = None
        self.stream = None
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.config = Path(self.directory.name) / "quota.json"
        self.summary = Path(self.directory.name) / "summary"
        self.configure("node-override")
        self.environment = {
            "QUOTA_ADMIN_SECRET": self.node_secret,
            "QUOTA_BILLING_ADMIN_SECRET": self.billing_secret,
            # The real secret is billing's base URL (the node's TINYCLOUD_QUOTA_URL).
            "QUOTA_BILLING_URL": "https://billing.example.invalid",
            "GITHUB_STEP_SUMMARY": str(self.summary),
        }
        for patcher in (
            patch.object(http.client, "HTTPSConnection", self.connection),
            patch("socket.create_connection", side_effect=AssertionError("Real network forbidden")),
            patch.dict(NS, {"CONFIG_PATH": self.config}),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        if "time" in NS:
            patcher = patch.object(NS["time"], "sleep")
            patcher.start()
            self.addCleanup(patcher.stop)

    def configure(self, authority):
        self.config.write_text(json.dumps({"authority": authority, "overrides": {
            space: {"limit_bytes": limit, "_comment": "Reviewed synthetic target"}
            for space, limit in LIMITS.items()
        }}))

    def connection(self, host, timeout, **kwargs):
        test = self
        self.assertIn(host, ["node.tinycloud.xyz", "billing.example.invalid"])
        self.assertGreater(timeout, 0)
        test.ports.append((host, kwargs.get("port")))

        class Connection:
            def request(self, method, path, body=None, headers=None):
                expected = test.node_secret if host == "node.tinycloud.xyz" else test.billing_secret
                test.assertTrue(headers.get("Authorization") == "Bearer " + expected,
                                "Distinct credentials must remain in their own TLS headers")
                test.assertFalse(test.node_secret in path or test.billing_secret in path)
                test.calls.append((host, method, path))
                if host == "billing.example.invalid" and test.transport_failures:
                    test.transport_failures -= 1
                    raise OSError(test.billing_secret)
                if host == "billing.example.invalid":
                    test.assertTrue(path.startswith("/api/admin/storage-comp/"),
                                    "Billing paths are fixed, never derived from the operator URL")
                self.method, self.path = method, path
                if method == "PUT" and test.apply_put:
                    test.values[unquote(path.rsplit("/", 1)[1])] = json.loads(body)["limit_bytes"]

            def getresponse(self):
                if host == "billing.example.invalid":
                    space = unquote(self.path.rsplit("/", 1)[1])
                    status = test.billing_status[space]
                    body = test.billing_body[space] if status == 200 else test.billing_secret
                elif test.node_status != 200:
                    status, body = test.node_status, test.node_secret
                elif self.path == "/admin/usage" and test.usage_body is not None:
                    status, body = 200, test.usage_body
                elif self.path == "/admin/usage":
                    status, body = 200, {"count": len(test.usage), "spaces": test.usage}
                else:
                    space = unquote(self.path.rsplit("/", 1)[1])
                    value = test.values.get(space)
                    status, body = 200, {"space_id": space, "override_bytes": value,
                                         "effective_limit_bytes": (value + int(test.bad_effective)) if value is not None else 123,
                                         "current_usage_bytes": 10}

                # Stream semantics of http.client.HTTPResponse.read(amt): at most
                # amt bytes per call, b"" once the body is exhausted.
                stream = io.BytesIO(body if isinstance(body, bytes) else json.dumps(body).encode())
                test.stream = stream
                response = type("Response", (), {"read": lambda _, count: stream.read(count)})()
                response.status = status
                return response

            def close(self):
                pass
        return Connection()

    def run_main(self, args=()):
        output = io.StringIO()
        with patch.dict(NS["os"].environ, self.environment, clear=True):
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                code = NS["main"](list(args))
        logs = output.getvalue() + (self.summary.read_text() if self.summary.exists() else "")
        self.assertFalse(any(value in logs for value in [*CANARIES, *LIMITS]),
                         "Secret, raw response or full space identity leaked")
        return code, logs

    def puts(self):
        return [call for call in self.calls if call[1] in ("PUT", "DELETE")]

    def billing_active(self):
        for space, limit in LIMITS.items():
            self.billing_status[space] = 200
            # Incremental comp intentionally below the absolute per-space floor.
            self.billing_body[space] = {"active": True, "comp_bytes": 1,
                                        "account_limit_bytes": limit + 100,
                                        "storage_limit_bytes": limit + 100}

    def test_legacy_404_checks_both_authorities_before_any_put(self):
        code, logs = self.run_main()
        self.assertEqual(code, 0)
        self.assertIn("billing storage-comp unavailable", logs)
        self.assertEqual(sorted(self.values.values()), sorted(LIMITS.values()))
        first_put = next(index for index, call in enumerate(self.calls) if call[1] == "PUT")
        self.assertEqual(sum(call[0] == "billing.example.invalid" for call in self.calls[:first_put]), 2)
        self.assertEqual([call[1] for call in self.calls], ["GET"] * 3 + ["PUT", "GET", "PUT", "GET"])

    def test_valid_inactive_200_allows_reviewed_legacy_restore(self):
        for space in LIMITS:
            self.billing_status[space] = 200
        self.assertEqual(self.run_main()[0], 0)
        self.assertEqual(len(self.puts()), 2)

    def test_active_comp_on_second_space_blocks_every_legacy_put(self):
        self.billing_active()
        first = next(iter(LIMITS))
        self.billing_body[first]["active"] = False
        code, logs = self.run_main()
        self.assertEqual(code, 1)
        self.assertEqual(self.puts(), [])
        self.assertIn("authority mismatch: flip to billing", logs)

    def test_billing_http_errors_are_not_absence_or_retried(self):
        first = next(iter(LIMITS))
        for status in (401, 403, 500, 503):
            with self.subTest(status=status):
                self.calls.clear()
                self.billing_status[first] = status
                self.assertEqual(self.run_main()[0], 1)
                self.assertEqual(self.puts(), [])
                self.assertEqual(sum(call[0] == "billing.example.invalid" for call in self.calls), 1)

    def test_malformed_billing_body_is_not_absence(self):
        first = next(iter(LIMITS))
        self.billing_status[first] = 200
        for body in ({}, {"active": "false"}, {"active": False},
                     {"active": False, "comp_bytes": True, "account_limit_bytes": 1, "storage_limit_bytes": None}):
            with self.subTest(case=type(body.get("active")).__name__):
                self.calls.clear()
                self.billing_body[first] = body
                self.assertEqual(self.run_main()[0], 1)
                self.assertEqual(self.puts(), [])

    def test_transport_retry_is_bounded_without_details(self):
        self.transport_failures = 2
        self.assertEqual(self.run_main()[0], 0)
        self.calls.clear()
        self.transport_failures = 10
        self.assertEqual(self.run_main()[0], 1)
        self.assertEqual(sum(call[0] == "billing.example.invalid" for call in self.calls), 3)
        self.assertEqual(self.puts(), [])

    def test_billing_mode_uses_absolute_limit_and_accepts_cold_node_cache(self):
        self.configure("billing")
        self.billing_active()
        code, logs = self.run_main()
        self.assertEqual(code, 0)
        self.assertEqual(self.puts(), [])
        self.assertIn("billing-authoritative; the node fetches on the next write (≤60 s TTL)", logs)

    def test_billing_absent_inactive_or_insufficient_fails_without_mutation(self):
        self.configure("billing")
        for variant in ("404", "inactive", "insufficient", "unknown-limit"):
            with self.subTest(case=variant):
                self.billing_active()
                first = next(iter(LIMITS))
                if variant == "404":
                    self.billing_status[first] = 404
                elif variant == "inactive":
                    self.billing_body[first]["active"] = False
                elif variant == "insufficient":
                    self.billing_body[first]["storage_limit_bytes"] = LIMITS[first] - 1
                else:
                    self.billing_body[first]["storage_limit_bytes"] = None
                self.assertEqual(self.run_main()[0], 1)
                self.assertEqual(self.puts(), [])

    def test_stale_local_override_rejects_billing_mode(self):
        self.configure("billing")
        self.billing_active()
        self.values[next(iter(LIMITS))] = 1
        code, logs = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("stale legacy override", logs)
        self.assertEqual(self.puts(), [])

    def test_unapplied_legacy_put_fails_readback(self):
        self.apply_put = False
        self.assertEqual(self.run_main()[0], 1)
        self.assertEqual(len(self.puts()), 1)

    def test_missing_unknown_authority_fails_validate_only_without_requests(self):
        for value in (None, "unknown"):
            with self.subTest(case=value):
                self.configure(value)
                if value is None:
                    document = json.loads(self.config.read_text())
                    del document["authority"]
                    self.config.write_text(json.dumps(document))
                self.assertEqual(self.run_main(["--validate-only"])[0], 1)
                self.assertEqual(self.calls, [])

    def test_missing_billing_secret_fails_preflight_without_requests(self):
        self.environment.pop("QUOTA_BILLING_ADMIN_SECRET")
        self.assertEqual(self.run_main(["--preflight"])[0], 1)
        self.assertEqual(self.calls, [])

    def test_preflight_does_not_require_a_healthy_node_or_mutate(self):
        self.assertEqual(self.run_main(["--preflight"])[0], 0)
        self.assertEqual(self.calls, [])

    def test_billing_base_url_and_compat_path_drive_the_full_restore(self):
        for url, port in (("https://billing.example.invalid", None), ("https://billing.example.invalid/", None),
                          ("https://billing.example.invalid:8443", 8443), ("https://billing.example.invalid/api/quota", None),
                          ("https://billing.example.invalid/api/quota/", None)):
            with self.subTest(url=url):
                self.calls.clear(); self.values.clear(); self.ports.clear()
                self.environment["QUOTA_BILLING_URL"] = url
                self.assertEqual(self.run_main(["--preflight"])[0], 0)
                self.assertEqual(self.calls, [])
                code, logs = self.run_main()
                self.assertEqual(code, 0)
                self.assertIn("Quota overrides verified", logs)
                self.assertEqual(sorted(self.values.values()), sorted(LIMITS.values()))
                self.assertEqual([call[1] for call in self.calls], ["GET"] * 3 + ["PUT", "GET", "PUT", "GET"])
                self.assertEqual([call[2].rsplit("/", 1)[0] for call in self.calls if call[0] == "billing.example.invalid"],
                                 ["/api/admin/storage-comp"] * 2)
                self.assertEqual({entry for entry in self.ports if entry[0] == "billing.example.invalid"},
                                 {("billing.example.invalid", port)})

    def test_incompatible_or_credential_bearing_billing_url_fails_without_requests(self):
        for url in ("", "billing.example.invalid", "http://billing.example.invalid", "http://billing.example.invalid/api/quota",
                    "https://billing.example.invalid/api", "https://billing.example.invalid/api/quota/x",
                    "https://billing.example.invalid/quota", "https://billing.example.invalid/unreviewed",
                    "https://billing.example.invalid//", "https://billing.example.invalid/api/quota//",
                    "https://user:password@billing.example.invalid", "https://user@billing.example.invalid/api/quota",
                    "https://@billing.example.invalid", "https://billing.example.invalid?key=bad",
                    "https://billing.example.invalid/api/quota?key=bad", "https://billing.example.invalid?",
                    "https://billing.example.invalid#fragment", "https://billing.example.invalid/api/quota#",
                    "https://", "https:///api/quota", "https://:8443", "https://billing.example.invalid:port",
                    "https://billing.example.invalid\n", "https://billing.example.invalid/api/quota\r\n",
                    "https://billing.exa\rmple.invalid", "https://billing.example.invalid/api/\tquota"):
            for args in (["--preflight"], []):
                with self.subTest(url=url.encode(), args=args):
                    self.environment["QUOTA_BILLING_URL"] = url
                    code, logs = self.run_main(args)
                    self.assertEqual(code, 1)
                    self.assertIn("billing quota URL has an incompatible shape", logs)
        self.assertEqual(self.calls, [])

    def test_effective_limit_and_override_must_both_match(self):
        self.bad_effective = True
        self.assertEqual(self.run_main()[0], 1)
        self.assertEqual(len(self.puts()), 1)

    def test_invalid_inventory_never_applies_either_override(self):
        first, second = list(LIMITS)
        for rows in ([{"space_id": first, "usage_bytes": 10}],
                     [{"space_id": first, "usage_bytes": 10}, {"space_id": second, "usage_bytes": None}],
                     [{"space_id": first, "usage_bytes": 10}, {"space_id": second, "usage_bytes": 0}],
                     [{"space_id": first, "usage_bytes": 10}, {"space_id": second, "usage_bytes": True}],
                     [{"space_id": first, "usage_bytes": 10}, {"space_id": first, "usage_bytes": 10}],
                     [{"space_id": self.node_secret, "usage_bytes": 10}]):
            with self.subTest(rows=len(rows)):
                self.calls.clear()
                self.usage = rows
                self.assertEqual(self.run_main()[0], 1)
                self.assertEqual(self.puts(), [])

    def test_prod_sized_inventory_drives_the_full_restore(self):
        self.usage_body = realistic_inventory(3000)
        self.assertGreater(len(self.usage_body), 4 * 65536)
        for authority in ("node-override", "billing"):
            with self.subTest(authority=authority):
                self.calls.clear(); self.values.clear()
                self.configure(authority)
                if authority == "billing":
                    self.billing_active()
                code, logs = self.run_main()
                self.assertEqual(code, 0)
                if authority == "billing":
                    self.assertIn("billing-authoritative", logs)
                    self.assertEqual(self.puts(), [])
                else:
                    self.assertIn("Quota overrides verified", logs)
                    self.assertEqual(sorted(self.values.values()), sorted(LIMITS.values()))
                    self.assertEqual([call[1] for call in self.calls], ["GET"] * 3 + ["PUT", "GET", "PUT", "GET"])

    def test_prod_sized_inventory_keeps_exact_target_invariants(self):
        document = json.loads(realistic_inventory(3000))
        first = next(iter(LIMITS))
        target = next(row for row in document["spaces"] if row["space_id"] == first)
        variants = {
            "missing": [row for row in document["spaces"] if row is not target],
            "duplicate": document["spaces"] + [dict(target)],
            "unknown-usage": [dict(row, usage_bytes=None) if row is target else row for row in document["spaces"]],
        }
        for name, rows in variants.items():
            with self.subTest(case=name):
                self.calls.clear()
                self.usage_body = json.dumps({"spaces": rows, "count": len(rows)}).encode()
                code, logs = self.run_main()
                self.assertEqual(code, 1)
                self.assertIn("no overrides applied", logs)
                self.assertEqual(self.puts(), [])

    def test_usage_body_is_bounded_at_the_documented_cap(self):
        inventory = realistic_inventory(3000)
        at_cap = inventory + b" " * (USAGE_CAP - len(inventory))
        self.usage_body = at_cap
        code, logs = self.run_main()
        self.assertEqual(code, 0, "A valid inventory of exactly the cap is accepted")
        self.calls.clear(); self.values.clear()
        self.usage_body = at_cap + b" "
        code, logs = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("quota API returned an invalid response", logs)
        self.assertEqual(self.calls, [("node.tinycloud.xyz", "GET", "/admin/usage")])
        self.assertLessEqual(self.stream.tell(), USAGE_CAP + 1, "The read stops at cap+1 bytes")

    def test_invalid_usage_body_fails_closed(self):
        inventory = realistic_inventory(3000)
        text = inventory.decode()
        # json.loads(bytes) auto-detects UTF-8-sig/16/32; the node only ever sends
        # plain UTF-8, so every other encoding (and gzip, which the script never
        # requests or decodes) must fail closed.
        for name, body in (("array", json.dumps(json.loads(inventory)["spaces"]).encode()),
                           ("truncated", inventory[:-1]), ("empty", b""), ("string", b'"spaces"'),
                           ("html", b"<html><body>502 Bad Gateway</body></html>"),
                           ("invalid-utf8", b"\xff" * 70000),
                           ("utf8-bom", b"\xef\xbb\xbf" + inventory),
                           ("utf16", text.encode("utf-16")), ("utf16-le", text.encode("utf-16-le")),
                           ("utf32-le", text.encode("utf-32-le")),
                           ("gzip", gzip.compress(inventory))):
            with self.subTest(case=name):
                self.calls.clear()
                self.usage_body = body
                code, logs = self.run_main()
                self.assertEqual(code, 1)
                self.assertIn("quota API returned an invalid response", logs)
                self.assertEqual(self.calls, [("node.tinycloud.xyz", "GET", "/admin/usage")])
        self.calls.clear()
        self.usage_body = inventory
        self.assertEqual(self.run_main()[0], 0, "Plain UTF-8 JSON is still accepted")

    def test_wrong_owner_config_fails_before_any_request(self):
        document = json.loads(self.config.read_text())
        document["overrides"] = {
            space.replace(OWNER, "tinycloud:pkh:eip155:1:0x" + "1" * 40): row
            for space, row in document["overrides"].items()
        }
        self.config.write_text(json.dumps(document))
        self.assertEqual(self.run_main()[0], 1)
        self.assertEqual(self.calls, [])

    def test_checked_in_full_target_and_value_contract(self):
        authority, overrides = NS["load_configuration"](ROOT / "ops/quota-overrides.json")
        self.assertIn(authority, ("node-override", "billing"))
        self.assertTrue(overrides == LIMITS, "Canonical Sam targets/values changed")

    def test_missing_node_secret_is_preflight_failure(self):
        self.environment.pop("QUOTA_ADMIN_SECRET")
        self.assertEqual(self.run_main(["--preflight"])[0], 1)
        self.assertEqual(self.calls, [])

    def test_node_http_error_does_not_retry_or_leak(self):
        self.node_status = 503
        self.assertEqual(self.run_main()[0], 1)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.puts(), [])


if __name__ == "__main__":
    unittest.main(testRunner=unittest.TextTestRunner(resultclass=SafeResult, verbosity=2))
