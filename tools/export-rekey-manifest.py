#!/usr/bin/env python3
"""Export public identities from a locally restored, custody-recorded backup.

No production endpoint is accepted. Output is canonical manifest bytes; terminal
output contains only its SHA-256 and network/seed counts.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
from urllib.parse import unquote, urlsplit


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("invalid exporter arguments")


def canonical_rows(records):
    rows, seen = [], set()
    for record in records:
        kind, network, path, version, public = record
        if kind == "network" and not public:
            continue  # Pending network with no allocated public key.
        if isinstance(public, bytes):
            public = public.hex()
        if (kind not in ("network", "seed") or not isinstance(network, str)
                or not network.startswith("urn:tinycloud:encryption:")
                or type(version) is not int or not 1 <= version < 2**63
                or not re.fullmatch("[0-9a-f]{64}", public)
                or (kind == "network" and path is not None)
                or (kind == "seed" and (not isinstance(path, str) or not path))):
            raise ValueError("invalid snapshot identity")
        identity = (kind, network, path, version)
        if identity in seen:
            raise ValueError("duplicate snapshot identity")
        seen.add(identity)
        rows.append(dict(kind=kind, network_id=network, key_path=path,
                         key_version=version, public_key=public))
    rows.sort(key=lambda r: (r["kind"], r["network_id"], r["key_path"] or "", r["key_version"]))
    return rows


def read_sqlite(path):
    for suffix in ("-wal", "-journal"):
        sidecar = Path(str(path) + suffix)
        if sidecar.exists() and sidecar.stat().st_size:
            raise ValueError("snapshot must be self-contained")
    with sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        networks = [("network", n, None, v, p) for n, v, p in db.execute(
            "SELECT network_id,key_version,public_key FROM encryption_network")]
        seeds = [("seed", n, k, v, p) for n, k, v, p in db.execute(
            "SELECT network_id,key_path,key_version,public_key FROM encryption_network_key")]
        return canonical_rows(networks + seeds)


def read_postgres(url, schema):
    if not url.startswith(("postgres://", "postgresql://")):
        raise ValueError("only lowercase PostgreSQL URLs are accepted")
    parsed = urlsplit(url)
    host = parsed.hostname
    if (parsed.scheme not in ("postgres", "postgresql") or parsed.query or parsed.fragment
            or "," in parsed.netloc
            or unquote(parsed.path).rstrip("/").endswith("/tinycloud-node-production-usw")):
        raise ValueError("only an explicit restored loopback database is accepted")
    # Accessing port validates the integer and range before libpq sees the URI.
    port = parsed.port
    if host not in ("localhost", "127.0.0.1", "::1") or (port is not None and port < 1):
        raise ValueError("only loopback is accepted")
    if not re.fullmatch("[a-zA-Z_][a-zA-Z0-9_]*", schema):
        raise ValueError("invalid restored schema")
    env = {k: v for k, v in os.environ.items() if not k.startswith("PG")}
    env.update(PGOPTIONS="-c default_transaction_read_only=on", PGPASSFILE=os.devnull)
    query = '''BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL search_path TO "SCHEMA";
SELECT json_build_array('network',network_id,NULL,key_version,encode(public_key,'hex')) FROM encryption_network;
SELECT json_build_array('seed',network_id,key_path,key_version,encode(public_key,'hex')) FROM encryption_network_key;
COMMIT;'''.replace("SCHEMA", schema)
    result = subprocess.run(["psql", "--no-psqlrc", "--no-password", "--quiet",
                             "--tuples-only", "--no-align", "--dbname", url,
                             "--set", "ON_ERROR_STOP=1", "--file", "-"],
                            input=query, capture_output=True, text=True, env=env, check=True)
    return canonical_rows([json.loads(line) for line in result.stdout.splitlines() if line])


def main(argv=None):
    parser = Parser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--sqlite-snapshot")
    source.add_argument("--restored-postgres-url")
    parser.add_argument("--schema", default="public")
    for flag in ("snapshot-file", "backup-id", "snapshot-timestamp", "exported-by",
                 "storage-location", "custody-record", "output"):
        parser.add_argument("--" + flag, required=True)
    args = parser.parse_args(argv)
    metadata = [args.backup_id, args.exported_by, args.storage_location, args.custody_record]
    if any(not value.strip() for value in metadata):
        raise ValueError("missing custody metadata")
    date = datetime.datetime.fromisoformat(args.snapshot_timestamp.replace("Z", "+00:00"))
    if (not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})", args.snapshot_timestamp)
            or date.tzinfo is None or date > datetime.datetime.now(datetime.timezone.utc)):
        raise ValueError("invalid snapshot date")
    if args.sqlite_snapshot and Path(args.sqlite_snapshot).resolve() != Path(args.snapshot_file).resolve():
        raise ValueError("SQLite snapshot must be the checksummed archive itself")
    archive_hash = hashlib.sha256()
    with open(args.snapshot_file, "rb") as archive:
        for block in iter(lambda: archive.read(1024 * 1024), b""):
            archive_hash.update(block)
    rows = (read_sqlite(args.sqlite_snapshot) if args.sqlite_snapshot else
            read_postgres(args.restored_postgres_url, args.schema))
    provenance = dict(source_database="tinycloud-node-production-usw", backup_id=args.backup_id,
                      snapshot_timestamp=args.snapshot_timestamp, snapshot_sha256=archive_hash.hexdigest(),
                      exported_by=args.exported_by, storage_location=args.storage_location,
                      custody_record=args.custody_record)
    document = dict(version=1, provenance=provenance, rows=rows)
    data = json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    with open(args.output, "xb") as output:
        output.write(data)
    print(json.dumps(dict(manifest_sha256=hashlib.sha256(data).hexdigest(),
                         networks=sum(r["kind"] == "network" for r in rows),
                         seeds=sum(r["kind"] == "seed" for r in rows)), separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("manifest export failed", file=sys.stderr)
        sys.exit(1)
