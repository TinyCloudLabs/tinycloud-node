# Space purge contract additions

- Write space ledger records at acceptance (`purging`) and completion, and owner-retirement records before acknowledging retirement. Owner keys use `_purge-ledger/owners/<key_id>/<owner-HMAC>`; all ledger objects live outside space prefixes.
- Each record carries a key ID, purge or retirement ID, state, timestamp, and a MAC under the persistent node tombstone key over those fields. Reconciliation acts only on records whose MAC verifies. Every reconciliation-triggered purge raises an alert containing counts and HMACs only.
- Before serving at startup or after restore, import owner retirements and reconcile space records. If the ledger is unreadable, refuse space reads and writes until reconciliation completes.
- Object Lock and IAM deny rules are deployment configuration. Code works without them; the deployment runbook identifies the operator's AWS configuration step.
- Phase 1 uses an explicit configured list of TinyCloud-operated hosts, each with a local retirement record and independent ledger. Registry write/import is phase 2.
- Add an owner-signed list-my-spaces route for complete enumeration of every app's spaces under that owner.

- `TINYCLOUD_HOST_ID` is a required non-secret stable host identifier for lifecycle routes, matching `[a-z0-9-]{1,63}`. Never derive it from the node DID. Phase-1 host configuration maps that ID to an exact HTTPS origin; registry mapping is phase 2.

- Ordinary live-space authentication behavior stays unchanged. For a non-owner, a purged or retired space enters the never-created-space path itself; do not hard-code 404 or normalize live permission misses. Load space and fence state on the same path, evaluate authority, then map the result. Raw-response tests derive the expected status, body and every header from the never-created case, with no grant and with a once-valid proof. Verified owner-rooted callers retain the 410 JSON envelope.
