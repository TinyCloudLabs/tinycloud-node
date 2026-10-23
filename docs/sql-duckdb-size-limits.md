# SQL and DuckDB size limits

These limits are enforced on `POST /invoke` for `tinycloud.sql/*` and `tinycloud.duckdb/*`. A refused request returns HTTP 413 with a plain-text body `<code>: <detail>`. The code is stable. The detail is human-readable and may change.

## Request bodies

The body is read after the invocation is authorized.

| Route | Limit | Code |
| --- | --- | --- |
| SQL `/invoke` | 2,097,152 bytes | `sql_request_too_large` |
| DuckDB `/invoke` | 1,048,576 bytes | `duckdb_request_too_large` |

The encryption decrypt path on `/invoke` uses 1,048,576 bytes and refuses with `request_too_large`. Meeting publication runs on the SQL `/invoke` path, so it uses the SQL limit of 2,097,152 bytes and refuses with `sql_request_too_large`.

The detail states the limit that was applied.

## Response bodies

| Route | Limit | Code |
| --- | --- | --- |
| SQL query | 10,485,760 bytes, or `maxBytes` if given | `sql_response_too_large` |
| DuckDB query | 10,485,760 bytes | `duckdb_response_too_large` |

- SQL `maxBytes` must be 1 to 4,194,304. It can only lower the 10 MiB limit.
- SQL `maxRows` must be 1 to 1,000. A query that returns more rows than `maxRows` is refused with `sql_response_too_large` and status 413. The detail states the row limit applied.
- DuckDB JSON responses are checked against an estimate of the serialized size. DuckDB Arrow responses are checked against the length of the encoded buffer.

## Not body-size limits

A storage-quota refusal is also HTTP 413, but its body is JSON with `"error":"storage_limit_reached"`. It means the write does not fit in the space's remaining storage. It is not a request or response size limit. See the storage section of the README.
