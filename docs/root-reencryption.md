# Resumable storage re-encryption

The node storage migration API in `tinycloud-core::reencrypt` moves existing
storage ciphertext to generation 2. It has no production root provider, CLI
activation flag, or change to the current ROOT acquisition path. The injectable
`NewRootSource` supplies independent new material; `Rings::from_source` retains
the existing generation 1 ROOT and the exact legacy column and seal keys.
Existing serving configuration continues selecting its existing keys.

## Storage behavior

Column and webhook keys retain #535's HKDF salt and purpose labels. A new
network-seal purpose separates the next seal key from both. Readers retain
legacy v1 keys, generation 1 purpose keys, and generation 0 seals. New writes
through the injected rings use generation 2. Client wrap-v1 and wrap-v2 envelopes
are unchanged: the job opens and re-seals server private keys and seeds, without
changing the underlying X25519 keys or any client ciphertext.

The inventory covers delegation and invocation serialization (including durable
read-audit invocations), hook secrets, both owner-share-policy byte fields, network
private keys, and named-key seeds. CID-alias rows hold hashes and an encryption
marker, not ciphertext. Delegation hashes and canonical aliases remain stable;
the job updates the alias encryption marker when converting plaintext storage.

Column rewrites retain the exact table, column and ordered PK binding from #535.
The network backend opens sealed bytes through stable purpose bindings with an
empty PK. Network public keys and available named-key public keys provide
identity checks during migration. Every migrated value is authenticated and
checked for byte-for-byte plaintext equality after it is written back.

## Activation and recovery

Before an integration calls `activate`, every serving instance must hold the
injected read rings and select the new writer. Activation installs SQLite or
PostgreSQL triggers and advances a durable singleton in one transaction. These
triggers reject stale encrypted inserts and changes, including writes behind the
cursor. Stale or keyless column writers also fail database construction after
activation. The migration does not change any root configuration itself.

Each `step` locks the singleton, processes at most the requested page size,
authenticates each value with its recorded kid and format, checks available
content identities, and compares-and-swaps ciphertext and format. It reads the
stored replacement back and verifies exact bytes, decryption and identity before
committing ciphertext, alias markers, cursor and counts together. An error stops
the page; dropping an interrupted transaction rolls it back. A committed page is
resumed by calling `step` again with the same rings. Multiple workers serialize
on the singleton. The final census requires no legacy, plaintext or other-kid
values before setting completion. Repeated calls after completion are idempotent.

`census` returns only table/column counts by kid plus legacy, plaintext and null
counts. `progress` returns only rewritten count and completion. Errors disclose
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
