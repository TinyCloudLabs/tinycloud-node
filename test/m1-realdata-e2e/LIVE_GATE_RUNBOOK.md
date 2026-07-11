# M1 live-gate PM runbook

The runner accepts no generated authority or canned evidence. Create five
fresh binary input files and two key files outside the repository, then point
the runner at them. Production command values must reference those file-path
environment variables; do not embed secret bytes in command strings.

```sh
export M1_RUN_ID="m1-$(date -u +%Y%m%dT%H%M%SZ)-PM_NONCE_LABEL"
export M1_RUN_NONCE_FILE=/pm/secure/run-nonce.bin
export M1_RENEWAL_NONCE_FILE=/pm/secure/renewal-nonce.bin
export M1_REVOKED_NONCE_FILE=/pm/secure/post-revoke-nonce.bin
export M1_SQL_SEED_FILE=/pm/secure/sql-seed.bin
export M1_KV_SEED_FILE=/pm/secure/kv-seed.bin
export M1_OWNER_PRIVATE_KEY_FILE=/pm/secure/owner.key
export M1_HOLDER_PRIVATE_KEY_FILE=/pm/secure/holder.key

export M1_NODE_REPO=/pm/candidates/tinycloud-node
export M1_POLICY_ENGINE_REPO=/pm/candidates/policy-engine
export M1_SDK_REPO=/pm/candidates/js-sdk
export M1_LISTEN_REPO=/Users/pmess/conductor/workspaces/listen/.smithers-data-exchange/direct-integ
export M1_OPEN_CREDENTIALS_REPO=/pm/candidates/opencredentials
export M1_NODE_DB=/pm/run-data/node/caps.db
export M1_PINNED_ARTIFACTS_FILE=/pm/secure/pinned-artifact-paths.txt

export M1_NODE_CMD='/pm/bin/start-real-node-for-m1'
export M1_NODE_READY_CMD='/pm/bin/wait-real-node-ready'
export M1_SEED_CMD='/pm/bin/seed-listen-schema-from-env-files'
export M1_DRIVER_PUBLISH_CMD='/pm/bin/run-vendored-m1-owner publish'
export M1_SIDECAR_CMD='/pm/bin/start-real-policy-sidecar-from-owner-state'
export M1_SIDECAR_READY_CMD='/pm/bin/wait-real-sidecar-ready'
export M1_REQUEST_INITIAL_CMD='/pm/bin/run-vendored-requester initial'
export M1_REQUEST_RENEW_CMD='/pm/bin/run-vendored-requester renew'
export M1_DRIVER_REVOKE_CMD='/pm/bin/run-vendored-m1-owner revoke'
export M1_REQUEST_DENIED_CMD='/pm/bin/run-vendored-requester renew-after-redeploy'
export M1_WAIT_EXPIRY_CMD='/pm/bin/wait-until-issued-delegation-expired'
export M1_POST_EXPIRY_READ_CMD='/pm/bin/run-vendored-requester native-read-after-expiry'

scripts/m1-gate-demo.sh "/pm/evidence/$M1_RUN_ID"
```

The production node and sidecar launchers choose free nonzero ports and write
them to `$M1_BUNDLE/node/port` and `$M1_BUNDLE/sidecar/port`. The phase
commands write the raw exchange envelopes documented in `README.md`; the
runner tees all stdout/stderr separately. `pinned-artifact-paths.txt` contains
one absolute regular-file path per line. The runner hashes each listed file.

Expected success output is the verifier JSON on stdout with
`"verdict":"pass"`, eleven passing assertions with citations, and
`"mutationSelfTest":"passed"`. The same JSON is saved as
`verifier-report.json`. Any missing raw field, dirty/wrong candidate checkout,
non-monotonic timestamp, altered resolve/import bytes, seed mismatch, TTL over
60 seconds, direct/preexisting imported child, wrong denial layer/code,
surviving process, or mutation accepted by the verifier exits nonzero.

The approved candidate prefixes are node `b51254e`, policy-engine `d72812a`,
js-sdk `5a42dd6`, Listen `bd936c0`, and OpenCredentials `a1633710`.
