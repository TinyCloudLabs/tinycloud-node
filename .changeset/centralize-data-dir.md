---
"core": minor
---

Add `datadir` config to centralize all data paths under a single root directory.

Previously, database, blocks, SQL, and DuckDB paths each had independent hardcoded defaults. Now all derive from `storage.datadir` (default: `./data`). Set `TINYCLOUD_STORAGE_DATADIR=/var/lib/tinycloud` to relocate all data with one variable. Individual paths can still be overridden explicitly.
