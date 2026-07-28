# Share addressed v2

The v2 request bodies in `vectors.json` are RFC 8785-style canonical JSON
(UTF-8, lexicographic object keys, no insignificant whitespace). Their
`requestBodyDigest` is the unpadded base64url SHA-256 of those exact bytes.
The digest field itself is excluded from its preimage. Consumers must reject
unknown fields and preserve the v1 exact-email preimage separately.
