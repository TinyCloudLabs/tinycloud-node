# M1 Denial Credential Fixtures

Deterministic launch-credential denial fixture package for amendment 26
(Sol-revised), confirmed from code: `opencredentials_verify @ ff47e55420f87552caf4e9144a0dfc748026e612`.

These fixtures are hand-authored SD-JWT presentations with fixed salts and
deterministic synthetic Ed25519 test keys. They intentionally do not call
`EmailCredentialIssuer::issue()` to reproduce bytes because issuer salting uses
`OsRng`.

The fixed invalid list is:

- wrong-issuer-signature
- untrusted-issuer-did
- wrong-vct
- subject-mismatch
- expired
- not-yet-valid
- missing-required-disclosure
- malformed-presentation
- enrollment-binding-mismatch

Each invalid fixture records `expectedVerifierRejection`, proven by the shipped
`EmailCredentialVerifier`, and `expectedEngineWireCode`, an integration
expectation for the policy-engine/g-03 layer rather than behavior proven by this
crate.

All key material is fixed-seed synthetic test material labeled NOT for
production. No credential-status revocation fixture is synthesized: TC-102
defers StatusList/status handling in v0, and the launch profile forbids
credential `status`, `cnf`, and `kb_jwt` claims.
