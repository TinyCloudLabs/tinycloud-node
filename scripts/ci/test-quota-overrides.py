#!/usr/bin/env python3
"""Exercise docker.yml's quota restoration against synthetic HTTP only."""

import contextlib
import io
import json
from pathlib import Path
import secrets
import tempfile
import re
import subprocess
import textwrap
import unittest
from unittest.mock import patch


WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/docker.yml"
SOURCE = WORKFLOW.read_text()
MARKER = "      - name: Restore storage quota overrides\n"
# Execute the actual inline implementation without its command entry point.
# No duplicated implementation or third-party YAML dependency is needed.
if MARKER not in SOURCE:
    raise SystemExit("FAIL: quota restoration step is absent")
BLOCK = SOURCE.split(MARKER, 1)[1]
SCRIPT = BLOCK.split("          python3 - <<'PY'\n", 1)[1].split("\n          PY", 1)[0]
NAMESPACE = {"__name__": "quota_workflow_test"}
exec(compile(textwrap.dedent(SCRIPT), str(WORKFLOW) + ":quota-restoration", "exec"), NAMESPACE)

APPLICATIONS = "tinycloud:pkh:eip155:1:0x" + "1" * 40 + ":applications"
SECRETS = "tinycloud:pkh:eip155:1:0x" + "1" * 40 + ":secrets"
OVERRIDES = {APPLICATIONS: 5368709120, SECRETS: 268721121}
CANARIES = []


class SecretSafeResult(unittest.TextTestResult):
    def _exc_info_to_string(self, error, test):
        output = super()._exc_info_to_string(error, test)
        for canary in CANARIES:
            output = output.replace(canary, "[sealed canary withheld]")
        return output


def quota_restore_enabled(context):
    condition = BLOCK.split("        if: >-\n", 1)[1].split("\n        env:", 1)[0].strip()[3:-2]
    return condition_enabled(condition, context)


def condition_enabled(condition, context):
    literals = []
    def protect(match):
        literals.append(match[0])
        return f"@{len(literals) - 1}@"
    condition = re.sub(r"'[^']*'", protect, condition)
    condition = re.sub(r"(?:github|inputs|steps|needs)\.[\w.-]+(?:\.[\w.-]+)*",
                       lambda match: repr(context.get(match[0], "")), condition)
    condition = condition.replace("success()", repr(context.get("job.success", True)))
    condition = condition.replace("always()", "True")
    condition = condition.replace("&&", " and ").replace("||", " or ")
    for index, literal in enumerate(literals):
        condition = condition.replace(f"@{index}@", literal)
    return bool(eval("(" + condition + ")", {"__builtins__": {}}, {}))


def config_document(overrides):
    return {space: {"limit_bytes": limit, "_comment": "Synthetic reviewed target"}
            for space, limit in overrides.items()}


class Response:
    def __init__(self, status, payload):
        self.status = status
        self.payload = payload

    def read(self, count):
        return self.payload[:count]


class QuotaTests(unittest.TestCase):
    def setUp(self):
        self.secret = secrets.token_urlsafe(32)
        CANARIES.append(self.secret)
        self.requests = []
        self.values = {}
        self.status = 200
        self.transport_failures = 0
        self.fail_method = None
        self.usage_rows = [{"space_id": space, "usage_bytes": 10} for space in OVERRIDES]
        self.applied = True
        self.wrong_effective = False
        self.patchers = [
            patch.object(NAMESPACE["http"].client, "HTTPSConnection", self.connection),
            patch.object(NAMESPACE["time"], "sleep"),
            patch("socket.create_connection", side_effect=AssertionError("Real network forbidden")),
        ]
        for patcher in self.patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def connection(self, host, timeout):
        self.assertEqual(host, "node.tinycloud.xyz")
        self.assertGreater(timeout, 0)
        test = self

        class Connection:
            def request(self, method, path, body=None, headers=None):
                test.requests.append((method, path, body, headers))
                if test.transport_failures and (test.fail_method is None or method == test.fail_method):
                    test.transport_failures -= 1
                    raise OSError(test.secret)
                self.method = method
                self.path = path
                if method == "PUT" and test.applied:
                    test.values[path] = json.loads(body)["limit_bytes"]

            def getresponse(self):
                if test.status != 200:
                    return Response(test.status, test.secret.encode())
                from urllib.parse import unquote
                if self.path == "/admin/usage":
                    return Response(200, json.dumps({
                        "spaces": test.usage_rows, "count": len(test.usage_rows),
                    }).encode())
                space = unquote(self.path.removeprefix("/admin/quota/"))
                override = test.values.get(self.path)
                effective = 1 if test.wrong_effective else override
                return Response(200, json.dumps({
                    "space_id": space,
                    "override_bytes": override,
                    "effective_limit_bytes": effective,
                }).encode())

            def close(self):
                pass

        return Connection()

    def apply(self):
        return NAMESPACE["apply_overrides"](OVERRIDES, self.secret)

    def test_applied_overrides_are_read_back_and_idempotent(self):
        self.apply()
        self.apply()
        self.assertEqual(len(self.requests), 10)
        self.assertEqual([r[0] for r in self.requests], ["GET", "PUT", "GET", "PUT", "GET"] * 2)
        self.assertTrue(self.requests[0][1] == self.requests[5][1] == "/admin/usage")
        self.assertEqual(sorted(self.values.values()), sorted(OVERRIDES.values()))
        for method, path, body, headers in self.requests:
            self.assertTrue(headers.get("Authorization") == "Bearer " + self.secret,
                            "Admin authorization must be passed as an HTTP header")
            self.assertFalse(self.secret in path, "Sealed canary leaked in a URL")
            if body:
                self.assertFalse(self.secret.encode() in body, "Sealed canary leaked in a request body")

    def test_successful_put_does_not_replace_get_verification(self):
        self.applied = False
        with self.assertRaises(NAMESPACE["QuotaError"]):
            self.apply()
        self.assertEqual([r[0] for r in self.requests], ["GET", "PUT", "GET"])

    def test_effective_limit_must_also_match(self):
        self.wrong_effective = True
        with self.assertRaises(NAMESPACE["QuotaError"]):
            self.apply()

    def test_http_5xx_is_not_retried_or_logged(self):
        self.status = 503
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
            with self.assertRaises(NAMESPACE["QuotaError"]):
                self.apply()
        self.assertEqual(len(self.requests), 1)
        self.assertFalse(self.secret in captured.getvalue(), "Sealed canary leaked in diagnostics")

    def test_transport_retry_is_bounded_and_idempotent(self):
        self.transport_failures = 2
        self.fail_method = "PUT"
        self.apply()
        self.assertEqual([r[0] for r in self.requests[:4]], ["GET", "PUT", "PUT", "PUT"])
        self.assertEqual(sorted(self.values.values()), sorted(OVERRIDES.values()))

    def test_transport_exhaustion_fails_without_error_details(self):
        self.transport_failures = 10
        with self.assertRaises(NAMESPACE["QuotaError"]) as error:
            self.apply()
        self.assertEqual(len(self.requests), 3)
        self.assertFalse(self.secret in str(error.exception), "Sealed canary leaked in an exception")

    def test_missing_authorization_never_requests(self):
        with self.assertRaises(NAMESPACE["QuotaError"]):
            NAMESPACE["apply_overrides"](OVERRIDES, "")
        self.assertEqual(self.requests, [])

    def test_reviewed_config_requires_exact_two_absolute_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "overrides.json"
            config.write_text(json.dumps(config_document(OVERRIDES)))
            self.assertEqual(NAMESPACE["load_overrides"](config), OVERRIDES)
            for bad in ({APPLICATIONS: 5368709120}, {APPLICATIONS: 5, SECRETS: 268721121},
                        {APPLICATIONS: True, SECRETS: 268721121}):
                config.write_text(json.dumps(config_document(bad)))
                with self.assertRaises(NAMESPACE["QuotaError"]):
                    NAMESPACE["load_overrides"](config)

    def test_main_failure_is_nonzero_and_has_safe_summary(self):
        self.status = 503
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "overrides.json"
            summary = Path(directory) / "summary"
            config.write_text(json.dumps(config_document(OVERRIDES)))
            output = io.StringIO()
            with patch.dict(NAMESPACE["os"].environ, {
                "QUOTA_ADMIN_SECRET": self.secret,
                "GITHUB_STEP_SUMMARY": str(summary),
            }), patch.dict(NAMESPACE, {"CONFIG_PATH": config}):
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                    self.assertEqual(NAMESPACE["main"](), 1)
            self.assertIn("FAILED", summary.read_text())
            self.assertFalse(self.secret in output.getvalue() + summary.read_text(), "Sealed canary leaked")

    def test_usage_inventory_must_prove_both_targets_before_any_put(self):
        bad_rows = [
            [{"space_id": APPLICATIONS, "usage_bytes": 10}],
            [{"space_id": APPLICATIONS, "usage_bytes": 10},
             {"space_id": SECRETS, "usage_bytes": None}],
            [{"space_id": APPLICATIONS, "usage_bytes": 10},
             {"space_id": SECRETS, "usage_bytes": 0}],
            [{"space_id": APPLICATIONS, "usage_bytes": 10},
             {"space_id": SECRETS, "usage_bytes": True}],
            [{"space_id": APPLICATIONS, "usage_bytes": 10},
             {"space_id": SECRETS, "usage_bytes": 10},
             {"space_id": SECRETS, "usage_bytes": 10}],
            [{"space_id": APPLICATIONS, "usage_bytes": 10},
             {"space_id": SECRETS + "-typo", "usage_bytes": 10}],
        ]
        for index, rows in enumerate(bad_rows):
            with self.subTest(case=index):
                self.requests.clear()
                self.usage_rows = rows
                with self.assertRaises(NAMESPACE["QuotaError"]):
                    self.apply()
                self.assertTrue(all(request[0] == "GET" for request in self.requests),
                                "No target may be mutated before both identities are proved")

    def test_checked_in_config_has_reviewed_absolute_limits(self):
        overrides = NAMESPACE["load_overrides"](WORKFLOW.parents[2] / "ops/quota-overrides.json")
        self.assertEqual(sorted(overrides.values()), sorted(OVERRIDES.values()))

    def test_inventory_failure_never_dumps_raw_space_rows(self):
        self.usage_rows = [{"space_id": self.secret, "usage_bytes": 10}]
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "overrides.json"
            summary = Path(directory) / "summary"
            config.write_text(json.dumps(config_document(OVERRIDES)))
            output = io.StringIO()
            with patch.dict(NAMESPACE["os"].environ, {
                "QUOTA_ADMIN_SECRET": self.secret, "GITHUB_STEP_SUMMARY": str(summary),
            }), patch.dict(NAMESPACE, {"CONFIG_PATH": config}):
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                    self.assertEqual(NAMESPACE["main"](), 1)
            self.assertTrue(all(request[0] == "GET" for request in self.requests))
            self.assertFalse(self.secret in output.getvalue() + summary.read_text(), "Raw inventory leaked")

    def test_snapshot_requires_explicit_n0_authorization_and_exact_image(self):
        digest = "sha256:4bdae4fc232d886bb56bfbce4ec62ed4b8fb4e1369a01f6afb73d06dd68c188f"
        selected = {
            "github.event_name": "workflow_dispatch", "github.ref": "refs/heads/main",
            "inputs.deploy_phala": True, "inputs.deploy_image_digest": digest,
            "inputs.restore_n0_quota_snapshot": True,
            "job.success": True, "needs.promote-watch.result": "success",
            "steps.pin.outputs.image": "ghcr.io/tinycloudlabs/tinycloud-node@" + digest,
            "steps.pin.outputs.version": "1.20.6",
            "steps.pin.outputs.image_label": "1.20.6-dstack",
            "steps.pin.outputs.revision": "e18578ff9162986ddd813259c60f73866e3e60d1",
        }
        self.assertTrue(quota_restore_enabled(selected))
        self.assertTrue(quota_restore_enabled({**selected, "needs.promote-watch.result": "failure"}),
                        "Watch scheduling must not block post-restart quota restoration")
        for changes in (
            {"inputs.restore_n0_quota_snapshot": False},
            {"inputs.deploy_image_digest": ""},
            {"inputs.deploy_image_digest": "sha256:" + "f" * 64},
            {"github.event_name": "release"},
            {"github.event_name": "push"},
            {"github.ref": "refs/tags/v1.20.6"},
            {"steps.pin.outputs.version": "1.20.7"},
            {"steps.pin.outputs.revision": "f" * 40},
            {"steps.pin.outputs.image": "ghcr.io/tinycloudlabs/tinycloud-node@sha256:" + "f" * 64},
            {"job.success": False},
        ):
            with self.subTest(fields=sorted(changes)):
                self.assertFalse(quota_restore_enabled({**selected, **changes}),
                                 "Unrelated deploy must not replay the reviewed snapshot")

    def test_partial_restart_failure_is_explicitly_unverified(self):
        report = SOURCE.split("      - name: Report unverified storage overrides\n", 1)[1]
        condition = report.split("        if: >-\n", 1)[1].split("\n        run:", 1)[0].strip()[3:-2]
        for attempted, outcome, enabled in (
            ("true", "failure", True), ("true", "skipped", True),
            ("true", "cancelled", True), ("true", "success", False),
            ("", "skipped", False),
        ):
            with self.subTest(attempted=attempted, outcome=outcome):
                self.assertEqual(condition_enabled(condition, {
                    "job.success": False,
                    "steps.deploy.outputs.cvm_mutation_attempted": attempted,
                    "steps.quotas.outcome": outcome,
                }), enabled)
        lines = []
        for line in report.split("        run: |\n", 1)[1].splitlines():
            if line and not line.startswith("          "):
                break
            lines.append(line)
        with tempfile.TemporaryDirectory() as directory:
            summary = Path(directory) / "summary"
            result = subprocess.run(["bash", "-e", "-c", textwrap.dedent("\n".join(lines))],
                                    env={"GITHUB_STEP_SUMMARY": str(summary), "QUOTA_ADMIN_SECRET": self.secret},
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("OVERRIDES UNVERIFIED", summary.read_text())
            self.assertFalse(self.secret in result.stdout + result.stderr + summary.read_text(),
                             "Partial-failure diagnostics must not expose authorization")


if __name__ == "__main__":
    unittest.main(testRunner=unittest.TextTestRunner(resultclass=SecretSafeResult, verbosity=2))
