# `/attestation` response and verification

`GET /attestation?nonce=<nonce>` returns a fresh TDX quote from the dstack
guest agent when the node runs in a dstack TEE (`--features dstack`). The
optional `nonce` must be 1-64 characters of `A-Z a-z 0-9 - _`; anything else
gets 400. The endpoint shares the public routes' per-IP rate limit (429).

**The node checks the binding is present; you must verify the quote.** Before
answering 200, the node parses the returned TDX v4 quote and requires its
REPORTDATA field (48-byte quote header, then TD report body offset 520; see
Intel's TDX DCAP Quoting Library API, Appendix A, "Version 4 Quote Format")
to equal `key_binding_sha256` followed by 32 zero bytes. This is a structural
check only. The node does not verify the quote's signature, certificate chain
or TCB status, so a 200 response proves nothing on its own.

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
- `timestamp` is the node's clock and is not covered by the quote. A quote
  requested without a nonce proves no freshness and can be replayed.
- If the node can't produce a quote, or the quote's REPORTDATA (or the guest
  agent's echo of it) is not the digest, or the quote is truncated or not a
  TDX v4 quote, the endpoint returns HTTP 503 `quote generation failed`.
  Earlier releases had no `key_binding_sha256` and answered quote failures
  with 200 and `mode: "classic"`.
- A node outside a TEE returns 200 with `mode: "classic"`. A verifier that
  expects a TEE must treat that as a failure.
- The quote binds `enforcer_did` to the measured node. It does not prove that
  the DID's private key was derived inside the TEE.

## Verifying

1. Choose a fresh, unpredictable nonce, for example 32 random bytes as
   unpadded base64url (43 characters), and request
   `/attestation?nonce=<nonce>`. Reject anything but 200 with
   `mode: "dstack"`.
2. Build the expected preimage yourself from the DID you expect and your
   nonce: `xyz.tinycloud.share/tee-key/v1\0:<expected DID>:<nonce>`. Check
   that it equals `key_binding` and that `enforcer_did` is the expected DID.
3. Compute SHA-256 of the preimage's UTF-8 bytes. It must equal
   `key_binding_sha256`.
4. Verify the quote (for example with dstack-verifier or Intel DCAP),
   including its TCB status, and read REPORTDATA from the verified quote,
   not from the response JSON. REPORTDATA must be the digest followed by 32
   zero bytes.
5. Check the TD report body yourself; quote verification doesn't apply this
   policy (Intel TDX DCAP Quoting Library API, §2.3.2 and Appendix A.3.4).
   TDATTRIBUTES must have the debug bit (TUD) clear, since a debug TD's memory
   is readable by the host.
6. Check the quote's MRTD and RTMR0-2 against the dstack OS image you trust.
   Replay `event_log` against RTMR3 and take `compose-hash` and `app-id` from
   the replayed events, not from the JSON fields. `compose-hash` is SHA-256 of
   the full app-compose JSON dstack deployed (compose file plus runner
   settings), so compare it with a trusted hash of that exact manifest for the
   release you expect, and check the manifest pins the expected image digests.

The digest only binds what the verifier recomputes in steps 2 and 3, so
always derive the preimage from your own nonce and expected DID rather than
trusting the returned string.
