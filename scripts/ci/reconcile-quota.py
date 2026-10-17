#!/usr/bin/env python3
"""Reconcile reviewed quota authority; secrets are accepted only through env."""
import argparse
import http.client
import json
import os
from pathlib import Path
import sys
import time
from urllib.parse import quote, urlsplit

CONFIG_PATH = Path("ops/quota-overrides.json")
OWNER = "tinycloud:pkh:eip155:1:0xd559CCd9EB87c530A9a349262669386dE93cf412"
LIMITS = {"applications": 5368709120, "secrets": 268721121}
NODE_HOST = "node.tinycloud.xyz"


class QuotaError(Exception):
    """A fixed, safe diagnostic; never wrap response or credential contents."""


def load_configuration(path):
    """Require an explicit reviewed authority and the two canonical targets."""
    try:
        document = json.loads(path.read_text())
        if not isinstance(document, dict) or set(document) != {"authority", "overrides"}:
            raise ValueError
        authority = document["authority"]
        if authority not in ("node-override", "billing"):
            raise ValueError
        rows = document["overrides"]
        expected = {f"{OWNER}:{name}": limit for name, limit in LIMITS.items()}
        if not isinstance(rows, dict) or set(rows) != set(expected):
            raise ValueError
        for space, row in rows.items():
            if (not isinstance(row, dict) or set(row) != {"limit_bytes", "_comment"}
                or type(row["limit_bytes"]) is not int or row["limit_bytes"] != expected[space]
                or not isinstance(row["_comment"], str) or not row["_comment"]):
                raise ValueError
        return authority, expected
    except (OSError, ValueError, TypeError):
        raise QuotaError("reviewed quota configuration is invalid") from None


def credentials():
    """Validate presence before compose mutation, without contacting services."""
    node = os.environ.get("QUOTA_ADMIN_SECRET", "")
    billing = os.environ.get("QUOTA_BILLING_ADMIN_SECRET", "")
    if not node or not billing or any("\r" in value or "\n" in value for value in (node, billing)):
        raise QuotaError("required runner quota credentials are missing or invalid")
    try:
        url = urlsplit(os.environ.get("QUOTA_BILLING_URL", ""))
        if (url.scheme != "https" or not url.hostname or url.username or url.password
            or url.path.rstrip("/") != "/api/quota" or url.query or url.fragment):
            raise ValueError
        port = url.port
    except ValueError:
        raise QuotaError("billing quota URL has an incompatible shape") from None
    return node, billing, (url.hostname, port)


def request_json(host, method, path, secret, limit=None, port=None, allow_404=False):
    """Fixed TLS requests, no redirects; retry transport only, never HTTP errors."""
    headers = {"Authorization": "Bearer " + secret, "Content-Type": "application/json"}
    body = None if limit is None else json.dumps({"limit_bytes": limit}).encode()
    for attempt in range(3):
        connection = None
        try:
            kwargs = {"timeout": 15}
            if port is not None:
                kwargs["port"] = port
            connection = http.client.HTTPSConnection(host, **kwargs)
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            payload = response.read(65537)
        except (OSError, http.client.HTTPException):
            if attempt == 2:
                raise QuotaError("quota transport failed after bounded attempts") from None
            time.sleep(attempt + 1)
            continue
        finally:
            if connection is not None:
                connection.close()
        if response.status == 404 and allow_404:
            return None
        if response.status != 200:
            raise QuotaError("quota API rejected the request")
        try:
            result = json.loads(payload) if len(payload) <= 65536 else None
            if not isinstance(result, dict):
                raise ValueError
            return result
        except (ValueError, UnicodeError):
            raise QuotaError("quota API returned an invalid response") from None


def prove_inventory(overrides, node_secret):
    """A quota GET echoes arbitrary IDs; only usage enumerates existing spaces."""
    inventory = request_json(NODE_HOST, "GET", "/admin/usage", node_secret)
    rows = inventory.get("spaces")
    if (not isinstance(rows, list) or type(inventory.get("count")) is not int
        or inventory["count"] != len(rows)):
        raise QuotaError("space inventory is invalid; no overrides applied")
    usage = {}
    for row in rows:
        if (not isinstance(row, dict) or not isinstance(row.get("space_id"), str)
            or row["space_id"] in usage):
            raise QuotaError("space inventory is ambiguous; no overrides applied")
        usage[row["space_id"]] = row.get("usage_bytes")
    if any(type(usage.get(space)) is not int or usage[space] <= 0 for space in overrides):
        raise QuotaError("both exact quota targets require positive known usage; no overrides applied")


def billing_comp(space, billing_secret, origin):
    """Read PR48's absolute per-space limit, not incremental account comp_bytes."""
    result = request_json(origin[0], "GET", "/api/admin/storage-comp/" + quote(space, safe=""),
                          billing_secret, port=origin[1], allow_404=True)
    if result is None:
        print("billing storage-comp unavailable")
        return None
    if (type(result.get("active")) is not bool
        or type(result.get("comp_bytes")) is not int or result["comp_bytes"] < 0
        or type(result.get("account_limit_bytes")) is not int or result["account_limit_bytes"] < 0
        or "storage_limit_bytes" not in result
        or (result["storage_limit_bytes"] is not None
            and (type(result["storage_limit_bytes"]) is not int or result["storage_limit_bytes"] < 0))):
        raise QuotaError("billing storage-comp returned an unexpected body")
    print("billing storage-comp active" if result["active"] else "billing storage-comp inactive")
    return result


def reconcile(authority, overrides, node_secret, billing_secret, billing_origin):
    """Prove both identities and both authority answers before any node PUT."""
    prove_inventory(overrides, node_secret)
    comps = {space: billing_comp(space, billing_secret, billing_origin) for space in overrides}
    if authority == "node-override":
        if any(comp is not None and comp["active"] for comp in comps.values()):
            raise QuotaError("authority mismatch: flip to billing")
        for space, limit in overrides.items():
            path = "/admin/quota/" + quote(space, safe="")
            request_json(NODE_HOST, "PUT", path, node_secret, limit)
            actual = request_json(NODE_HOST, "GET", path, node_secret)
            if (actual.get("space_id") != space or type(actual.get("override_bytes")) is not int
                or actual["override_bytes"] != limit or type(actual.get("effective_limit_bytes")) is not int
                or actual["effective_limit_bytes"] != limit):
                raise QuotaError("quota override and effective limit did not both verify")
        return "Quota overrides verified: applications=5368709120; secrets=268721121."
    for space, floor in overrides.items():
        comp = comps[space]
        if (comp is None or not comp["active"] or type(comp["storage_limit_bytes"]) is not int
            or comp["storage_limit_bytes"] < floor):
            raise QuotaError("billing authority does not cover both reviewed quota floors")
        actual = request_json(NODE_HOST, "GET", "/admin/quota/" + quote(space, safe=""), node_secret)
        if actual.get("space_id") != space or "override_bytes" not in actual:
            raise QuotaError("node quota readback is invalid")
        if actual["override_bytes"] is not None:
            raise QuotaError("stale legacy override")
    return "billing-authoritative; the node fetches on the next write (≤60 s TTL)"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--validate-only", action="store_true")
    modes.add_argument("--preflight", action="store_true")
    args = parser.parse_args(argv)
    try:
        authority, overrides = load_configuration(CONFIG_PATH)
        if args.validate_only:
            print("Reviewed quota authority and targets validated.")
            return 0
        node_secret, billing_secret, origin = credentials()
        if args.preflight:
            print("Runner quota credentials and billing URL validated; no service requests.")
            return 0
        message = reconcile(authority, overrides, node_secret, billing_secret, origin)
        code = 0
    except QuotaError as error:
        message = f"Quota restoration FAILED: {error}. Authorized operator fallback required."
        code = 1
    except Exception:
        message = "Quota restoration FAILED: unexpected error; details withheld. Authorized operator fallback required."
        code = 1
    print(("::error::" if code else "") + message)
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a") as summary:
            summary.write(message + "\n")
    return code


if __name__ == "__main__":
    sys.exit(main())
