# Space purge contract additions

Verified frozen amendments: v1.5 contract `8b9bfdab43b78f11edcf5c76efbb71c4d2db109c6b2a95d37f91cf8f219cf494`, vectors `ecb7fb4e891f650a8903584dc9bb7745fa582643716874c6678ddf8c8987162e`; v1.6 contract `9810fb9a6167a860c06d35e3a4e8a28447f9c9f48b0bc02f2adcc3749a71c4b5`, vectors `4100f762b6f63c39441bfc0f75978eb7982c5f1e896f7de786587d8ccb562aa1`. These extend the immutable v1.4 baseline. The prefix-HMAC v1.7 amendment below is pending freeze.

- Write space ledger records at acceptance (`purging`) and completion, and owner-retirement records before acknowledging retirement. Owner keys use `_purge-ledger/owners/<key_id>/<owner-HMAC>`; all ledger objects live outside space prefixes.
- Each record carries a key ID, purge or retirement ID, state, timestamp, and a MAC under the persistent node tombstone key over those fields. Reconciliation acts only on records whose MAC verifies. Every reconciliation-triggered purge raises an alert containing counts and HMACs only.
- Before serving at startup or after restore, import owner retirements and reconcile space records. If the ledger is unreadable, refuse space reads and writes until reconciliation completes.
- Object Lock and IAM deny rules are deployment configuration. Code works without them; the deployment runbook identifies the operator's AWS configuration step.
- Phase 1 uses an explicit configured list of TinyCloud-operated hosts, each with a local retirement record and independent ledger. Registry write/import is phase 2.
- Add an owner-signed list-my-spaces route for complete enumeration of every app's spaces under that owner.

- `TINYCLOUD_HOST_ID` is a required non-secret stable host identifier for lifecycle routes, matching `[a-z0-9-]{1,63}`. Never derive it from the node DID. Phase-1 host configuration maps that ID to an exact HTTPS origin; registry mapping is phase 2.

- Ordinary live-space authentication behavior stays unchanged. For a non-owner, a purged or retired space enters the never-created-space path itself; do not hard-code 404 or normalize live permission misses. Load space and fence state on the same path, evaluate authority, then map the result. Raw-response tests derive the expected status, body and every header from the never-created case, with no grant and with a once-valid proof. Verified owner-rooted callers retain the 410 JSON envelope.

- Acceptance records authenticate a keyed HMAC of every exact physical storage prefix used by the space, including a long name's hashed SQL object prefix. Restore reconciliation enumerates actual prefixes and matches their HMACs; it never reverses an HMAC, retains an encrypted SpaceId mapping, guesses ownership, or deletes unmatched prefixes. A backend remains unavailable until this reconciliation is supported.
- A verified completion ledger entry is an irreversible fence, not proof that the database cleanup transaction committed. Startup must redo any remaining cleanup before serving restored rows.
