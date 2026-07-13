#!/usr/bin/env bash
set -Eeuo pipefail
DB=$1 RUN_ID=$2 OUTPUT=$3
[[ -f "$DB" ]] || { printf 'node DB not found: %s\n' "$DB" >&2; exit 2; }
python3 - "$DB" "$RUN_ID" "$OUTPUT" <<'PY'
import datetime, json, sqlite3, sys
db, run_id, output = sys.argv[1:]
connection = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
connection.row_factory = sqlite3.Row
def rows(table):
    present = connection.execute("select 1 from sqlite_master where type='table' and name=?", (table,)).fetchone()
    if not present:
        raise RuntimeError(f"required node authority table is missing: {table}")
    return [dict(row) for row in connection.execute(f'SELECT * FROM "{table}" ORDER BY rowid')]
def safe(value):
    if isinstance(value, bytes):
        import base64
        return {"base64": base64.urlsafe_b64encode(value).decode().rstrip("=")}
    return value
data = {
    "runId": run_id,
    "observedAt": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
    "database": db,
    "delegations": [{k: safe(v) for k, v in row.items()} for row in rows("delegation")],
    "abilities": [{k: safe(v) for k, v in row.items()} for row in rows("ability")],
    "parentDelegations": [{k: safe(v) for k, v in row.items()} for row in rows("parent_delegation")],
}
with open(output, "x", encoding="utf-8") as handle:
    json.dump(data, handle, separators=(",", ":"), sort_keys=True)
    handle.write("\n")
PY
