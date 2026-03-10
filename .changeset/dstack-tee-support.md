---
"tinycloud": minor
---

Add dstack TEE support for confidential deployment. Keys can now be derived deterministically from TEE KMS, sensitive database columns are encrypted with AES-256-GCM, and a new `/attestation` endpoint provides TDX hardware attestation quotes. The `/version` endpoint now includes an `inTEE` flag. Enabled via `--features dstack`.
