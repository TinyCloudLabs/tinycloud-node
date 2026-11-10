# Resumable storage re-encryption

The node storage migration API in `tinycloud-core::reencrypt` moves existing
storage ciphertext to generation 2. It has no production root provider, CLI
activation flag, or change to the current ROOT acquisition path. The injectable
`NewRootSource` supplies independent new material; `Rings::from_source` retains
the existing generation 1 ROOT and the exact legacy column and seal keys.
Existing serving configuration continues selecting its existing keys.

## Deployment restriction

This PR must ship only as part of the TC-2713 rotation event. Do not deploy it
standalone to a node holding v1 network-key or seed rows. Before deployment,
the rotation integration must have a production-wired migration runner, a
verified snapshot manifest and custody record, and an offline migration window
with serving stopped. Migrate and verify all existing material before resuming
serving. Unmigrated v1 requests return HTTP 503 with `migration_required`.

The library's `manifest::run_offline` entry verifies a file and its separately
supplied digest before any database access, checks manifest coverage, and drives
the fenced job. It does not acquire production roots or install new serving
rings. Those integration steps remain prerequisites for the rotation event.

## Storage behavior

Column and webhook keys retain #535's HKDF salt and purpose labels. A new
network-seal purpose separates the next seal key from both. Column readers retain
legacy v1 keys and generation 1 purpose keys; migration retains legacy seal keys.
Serving accepts PK-bound v2 seals with generation 0 or 2. Injected rings initially
keep the existing writers and add generation 2 read keys. After activation commits,
the returned rings select generation 2 writers. Client wrap-v1 and wrap-v2 envelopes
are unchanged: the job opens and re-seals server private keys and seeds, without
changing the underlying X25519 keys or any client ciphertext.

The inventory covers delegation and invocation serialization (including durable
read-audit invocations), hook secrets, both owner-share-policy byte fields, network
private keys, and named-key seeds. CID-alias rows hold hashes and an encryption
marker, not ciphertext. Delegation hashes and canonical aliases remain stable;
the job updates the alias encryption marker when converting plaintext storage.

Column rewrites retain the exact table, column and ordered PK binding from #535.
Network private-key bindings include `network_id`; seed bindings include
`network_id` and `key_path` in database PK order. Serving opens and migration
verify the network private key against the row's public key. Named-key opens
also check the derived public key against the key row. Serving rejects v1 private-key
and seed seals. Only the migration may decode legacy seals after checking the
verified external manifest described below; rewritten seals use PK-bound v2.
Every migrated value is authenticated and checked for byte-for-byte plaintext
equality after it is written back.

## Legacy seal migration prerequisites

Both networks and seeds require one externally pinned manifest from a dated,
trusted PlanetScale backup of `tinycloud-node-production-usw`, exported from a
local restored snapshot. The [manifest format and export procedure](rekey-manifest.md)
define its canonical encoding, snapshot checksum, custodian and custody record.
The expected manifest SHA-256 must be recorded separately before the window.
The target database must never supply its own trusted identities or expected pin.

`VerifiedManifest` can be constructed only by checking the bytes against that
separate pin, the required provenance metadata, canonical encoding and identities.
Every `step` accepts this verified input, with no raw-map constructor or fallback.
For v1 network seals, the manifest entry `(network_id, key_version)` must equal
the stored public key and the public key derived from the private key. For v1
seeds, `(network_id, key_path, key_version)` must equal the derived named-key
public key and the stored public key.

Network ceremonies are additional database consistency checks, not independent
provenance. Exactly one completed `initial` ceremony, a completion record, no
failure and `transcript_hash = hash_hex(public_key)` are required in addition to
the external manifest. A missing or mismatching manifest entry or inconsistent
ceremony aborts the page, preserves ciphertext/checkpoint, and prevents completion
and old-root retirement.

The runner reports missing or mismatched identities as counts-only blocking
coverage categories; it never skips them. Networks or seeds created after the
snapshot require a fresh trusted snapshot immediately before the migration
window. Authenticated client-held public-key pins may become a later second
source. Client-wrapped key v1 and v2 protocols remain unchanged.

## Activation and recovery

The rollout order is read overlap, database fence, then writer switch. First,
install the injected rings on every serving instance with old writer kids
(columns/webhooks 1 and seals 0), retaining all required old and new read keys.
The schema's overlap guards keep kid 2 read-only before activation.
`activate` validates that overlap, installs SQLite or PostgreSQL triggers, and
advances the durable singleton in one transaction. Only after that transaction
commits does it return rings selecting writer kid 2. Switch serving writers to
those returned rings; stale writes are rejected by the database fence.

`SpaceDatabase::new_with_storage_rings` checks the column, webhook and seal rings
against one locked activation snapshot, holding the lock through alias backfill.
Before activation, overlap rings must retain their old writers. After activation,
all three rings must select the target writer and retain the required read
generations through authenticated verification. Key retirement remains a separate
integration step. The migration does not change any production root configuration
itself.

Each `step` locks the singleton, processes at most the requested page size,
authenticates each value with its recorded kid and format, checks available
content identities, and compares-and-swaps ciphertext and format. It reads the
stored replacement back and verifies exact bytes, decryption and identity before
committing ciphertext, alias markers, cursor and counts together. An error stops
the page; dropping an interrupted transaction rolls it back. A committed page is
resumed by calling `step` again with the same rings. Multiple workers serialize
on the singleton.

After rewriting, a durable verification phase starts from the beginning. Each
step reads at most one bounded page, validates required seal presence and row
state, requires the target format and kid, decrypts every value, checks content
identity, and checks delegation aliases. Missing network parents or required
sealed values stop the job. NULL values are accepted only for valid lifecycle
states that intentionally hold no material. Verification cursors and counts
commit with each checked page and resume after interruption.

Database mutation triggers invalidate the verification revision. A write during
verification restarts that bounded pass, so completion requires a complete
authenticated pass at one unchanged revision. Repeated calls after completion
are idempotent while that revision remains current.

`census` returns only table/column counts by kid plus legacy, plaintext and null
counts. `progress` returns only rewrite/verification counts, phase and completion. Errors disclose
no row identities, key material, plaintext or ciphertext. The database cursor
contains PKs and must be treated as database data, never logged. Database tracing
must not be configured to emit bound values during an operational migration.
The fencing migration refuses downgrade after activation; keep old roots until
verification and a separately approved retirement plan are complete.

## Identity and invitation rollout plan

Identity and invitation keys require a separate protocol rollout. No rotation
code for them is included here. First inventory client pins, cached node DIDs,
invitation verification kids, trust bundles and outstanding invitation expiry.
Publish the new node DID and invitation kid alongside the old entries before
changing either signing key. Distribute overlapping trust bundles, allow clients
to refresh caches, and verify that both identities are accepted across supported
clients and existing sessions. Keep issuance on the old key during publication.

Switch new signing and invitation issuance only after overlap adoption is
verified. Continue validating old signatures and outstanding invitations through
their supported lifetime; retain old public verification entries and explicit
kid selection throughout the overlap. Remove old signing access and later retire
old public entries only after client adoption, invitation expiry and rollback
requirements are satisfied. Storage re-encryption alone does not update clients,
rewrite signed delegation history or authorize identity retirement.
