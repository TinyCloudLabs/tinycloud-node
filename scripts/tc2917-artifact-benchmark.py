# /// script
# requires-python = ">=3.10"
# dependencies = ["psycopg[binary]>=3.2,<4"]
# ///
"""Local disposable PostgreSQL 18 only: uv run scripts/tc2917-artifact-benchmark.py URL.

Uses a temporary table, LZ4, the reader's 4 MiB substr queries, and verifies
identical bytes with SHA256. Reports backend CPU ticks (Linux USER_HZ=100),
wall time and storage. Three warm reads/layout; first read reported separately.
Does not flush shared buffers/OS caches: these are NOT cold-cache measurements.
"""
import hashlib
import json
import sys
import time

import psycopg


def cpu(conn):
    fields = conn.execute("SELECT pg_read_file('/proc/self/stat')").fetchone()[0].split()
    return (int(fields[13]) + int(fields[14])) / 100


with psycopg.connect(sys.argv[1], autocommit=True) as conn:
    assert conn.info.host in ("127.0.0.1", "localhost"), "local benchmark only"
    conn.execute("CREATE TEMP TABLE tc2917_bench (payload bytea)")
    conn.execute("ALTER TABLE tc2917_bench ALTER COLUMN payload SET COMPRESSION lz4")
    for mib in (75, 150, 300):
        # Deterministic repeated page with some incompressible content, representing
        # a compressible DB. Record ratio; no claim it matches production exactly.
        page = b"".join(hashlib.sha256(str(i).encode()).digest() for i in range(8192)) + bytes(768 * 1024)
        payload = page * (mib * 1024 * 1024 // len(page))
        expected = hashlib.sha256(payload).digest()
        for storage in ("EXTENDED", "EXTERNAL"):
            conn.execute("TRUNCATE tc2917_bench")
            conn.execute(f"ALTER TABLE tc2917_bench ALTER COLUMN payload SET STORAGE {storage}")
            conn.execute("INSERT INTO tc2917_bench VALUES (%s)", (payload,))
            stored, compression = conn.execute(
                "SELECT pg_column_size(payload), pg_column_compression(payload) FROM tc2917_bench"
            ).fetchone()
            assert (compression == "lz4") if storage == "EXTENDED" else compression is None
            for run in range(4):
                digest = hashlib.sha256()
                start_cpu = cpu(conn)
                start = time.monotonic()
                for offset in range(0, len(payload), 4 * 1024 * 1024):
                    data = conn.execute(
                        "SELECT substr(payload, %s, %s) FROM tc2917_bench",
                        (offset + 1, min(4 * 1024 * 1024, len(payload) - offset)),
                        binary=True,
                    ).fetchone()[0]
                    digest.update(data)
                elapsed = time.monotonic() - start
                seconds = cpu(conn) - start_cpu
                assert digest.digest() == expected
                print(json.dumps(dict(mib=mib, storage=storage, stored_bytes=stored,
                                      compression=compression, run=run,
                                      cache="first" if run == 0 else "warm",
                                      backend_cpu_s=round(seconds, 3), elapsed_s=round(elapsed, 3))),
                      flush=True)
