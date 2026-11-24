# Container-recreate drill (TC-1491 P4.2b, part 1)

Design doc: `docs/sql-store-master-design.md`, section 12 (P4.2b) and section 14.

## The question

If the node container is recreated (a deploy) or killed (a crash, an OOM kill), do
we still have every SQL write the node told the client it had saved?

Today the answer should be yes, because Postgres is the master copy and the node
rebuilds its local file from it. That is a claim from code and docs, not from a
log (section 14). This drill checks it. It then checks the layout P4.2b proposes:
the SQL datadir (`/data/sql`) on a named volume, which is what a store-master
database will need, because for a store-master database the local file is the
only copy of the writes since the last publish.

## What it does

For each layout, `drill.sh` starts the node with throwaway Postgres and LocalStack S3,
signs in with a throwaway key, and writes numbered rows with the TinyCloud SDK. The
client keeps a ledger: it records a write before sending it, and records an
acknowledgement when the node answers `ok`. Then, in order:

1. **Recreate** the container (`up --force-recreate`): what a deploy does.
2. **SIGKILL** the container while a writer is running, then start the same container
   again: a crash or OOM kill. The writable layer survives this.
3. **SIGKILL** while a writer is running, then **recreate**: a crash during a deploy.

After each step, with no request sent yet, it counts the files under `/data/sql` in the
container (`docker cp`, since the image is `FROM scratch`). Then it reads every row
back. The rules are:

* every row the node acknowledged must come back with exactly the value written;
* a write the node never answered (the kill came mid-request) may be there or not;
* a row the ledger never heard of fails the drill;
* with no volume, the file is gone after a recreate and the reads still succeed (that is
  the re-hydration path working); with the volume, the file must still be there before
  the first request. If the no-volume layout keeps the file, the drill fails too,
  because it means section 14 is wrong and must be re-read.

## What it needs

* A host that may run containers and volumes freely: **an isolated CI runner or a
  Docker host you own.** The script refuses to run unless `CI=true` or
  `DRILL_ALLOW_LOCAL=1`. We do not run it on the shared dev machine (no Docker there).
* Docker with compose v2, `curl`, `openssl`, node 20+, and network access to pull
  `localstack`, `postgres:16`, `busybox:1.36` and the npm packages.
* The node image built from the checkout under test: `docker build -t tinycloud-node:drill .`
  (about 15 to 30 minutes cold; the workflow does this), then `DRILL_NODE_IMAGE=tinycloud-node:drill`.
* `npm ci` in this directory.
* A free port on 127.0.0.1 (18000 by default, `DRILL_PORT`). About 6 GB of disk and
  10 to 15 minutes for the drill itself.
* No production secret. The client key, the node's static key and the Postgres
  password are generated per run; Postgres has no volume and S3 is LocalStack.

```
cd test/recreate-drill
npm ci
CI=true DRILL_NODE_IMAGE=tinycloud-node:drill bash drill.sh all   # or: today | volume
```

The result is in `summary.txt` (the path is printed; `DRILL_SUMMARY` overrides it) and
ends in `DRILL PASSED` or `DRILL FAILED`. The summary holds counts and row ids only,
never a value or a key.

## What runs where

| Check | Where | Status |
|---|---|---|
| Ledger logic (`drill-core.test.ts`, 10 tests) and the TypeScript types | any machine with node | ran locally |
| `drill.sh` control flow against a fake `docker`/`curl`/`npx` (`test-drill.sh`, 4 cases and the CI guard) | any machine with bash | ran locally |
| The real drill, both layouts | CI (`.github/workflows/recreate-drill.yml`, manual dispatch or a change under `test/recreate-drill/`) or a Docker host | **not run**: Docker is not used on the dev machine, so the first CI run is the first real run. Expect to adjust the script once. |

## Known gaps, stated plainly

* **Both layouts are Postgres-master.** P4.2a does not cut any database over, so this
  drill cannot yet lose a write that only the volume holds. It proves the baseline
  (re-hydration works) and that the volume keeps the working copy. The store-master
  version (write to a cut-over database, kill, recreate, read back from the volume with
  Postgres stale) needs the P4.4 cutover and is run again then. The same ledger client
  and script are reused.
* **The volume needs the directory to exist and be owned by uid 1000.** The image is
  `FROM scratch` and runs as `tinycloud` (1000); a new named volume is root-owned, so
  the node could not write to it. The Dockerfile already does this for the deletion
  ledger (`mkdir` + `chown` at `/var/lib/tinycloud/ledger`). The P4.2b production change
  must do the same for `/data/sql`. The drill stands in for that with a `chown` on the
  volume before the node starts. Naomi/Amos: this is part of the compose/Dockerfile change.
* **This is not the staging drill.** Staging deploy, a CVM restart and an OS-image
  upgrade (P4.2b part 2) need a real CVM and are separate.
* **`docker kill` may be followed by Docker's own restart** (`restart: unless-stopped`
  as in production). The script tolerates that: it only needs the node back before it
  reads.
* **Not run by CI today.** The workflow is not a required check.
