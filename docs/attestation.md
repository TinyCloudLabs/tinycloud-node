# `/attestation` response and verification

`GET /attestation?nonce=<nonce>` returns a fresh TDX quote from the dstack
guest agent when the node runs in a dstack TEE (`--features dstack`).

## Response

```json
{
  "mode": "dstack",
  "quote": "<hex TDX quote>",
  "event_log": "<dstack event log>",
  "compose_hash": "<hex SHA-256 of app-compose.json>",
  "app_id": "<dstack app id>",
  "enforcer_did": "did:key:z6Mk...",
  "key_binding": "xyz.tinycloud.share/tee-key/v1\\0:did:key:z6Mk...:<nonce>",
  "key_binding_sha256": "<64 hex chars>",
  "timestamp": "<RFC 3339>"
}
```

- `key_binding` is the binding preimage:
  `xyz.tinycloud.share/tee-key/v1\0:<enforcer_did>:<nonce>`. The `\0` is two
  characters, a backslash and a zero (written `\\0` in JSON), not a NUL
  byte. Without a `nonce` query parameter the string ends in `:`.
- `key_binding_sha256` is the hex SHA-256 of the UTF-8 bytes of
  `key_binding`. The node sends these 32 bytes to dstack `GetQuote`, so the
  quote's 64-byte REPORTDATA is the digest followed by 32 zero bytes.
- If the node can't produce a quote, or the guest agent reports quoting
  different report data, the endpoint returns HTTP 503 with a
  `quote generation failed: ...` message. Earlier releases had no
  `key_binding_sha256` and answered that case with 200 and
  `mode: "classic"`.
- A node outside a TEE still returns 200 with `mode: "classic"`.

## Verifying

1. Choose a fresh, unpredictable nonce and request
   `/attestation?nonce=<nonce>`.
2. Build the expected preimage yourself from the DID you expect and your
   nonce: `xyz.tinycloud.share/tee-key/v1\0:<expected DID>:<nonce>`. Check
   that it equals `key_binding` and that `enforcer_did` is the expected DID.
3. Compute SHA-256 of the preimage's UTF-8 bytes. It must equal
   `key_binding_sha256`.
4. Verify the quote (for example with dstack-verifier or Intel DCAP) and
   read its REPORTDATA from the verified quote, not from the response JSON.
   REPORTDATA must be the digest followed by 32 zero bytes.
5. Replay `event_log` against the quote's RTMRs and check `compose_hash` and
   `app_id` against the measurements you trust.

The digest only binds what the verifier recomputes in steps 2 and 3, so
always derive the preimage from your own nonce and expected DID rather than
trusting the returned string.
