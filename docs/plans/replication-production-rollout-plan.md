# Replication Production Rollout Plan

Status: draft rollout plan for `feat/replication-e2e-bootstrap`

This document is the production rollout plan for the replication branch in `tinycloud-node`. It is an operations plan for merge, canary, registration, rollout, and rollback. It is not the protocol spec.

## 1. Current State and Rollout Scope

### Branch state

The branch already contains the first real replication surface in `tinycloud-node`:

- `/info` and `/replication/info` expose node capability advertisement.
- `/replication/session/open` issues short-lived replication session tokens after sync auth.
- `/replication/auth/export` and `/replication/auth/reconcile` support auth sync.
- `/replication/export`, `/replication/reconcile`, and `/replication/reconcile/split` support KV replay-style repair.
- `/replication/recon/export`, `/replication/recon/compare`, `/replication/recon/split`, and `/replication/recon/split/compare` provide the first Recon anti-entropy surface.
- `/replication/kv/state`, `/replication/kv/state/compare`, `/replication/peer-missing/plan`, `/replication/peer-missing/apply`, and `/replication/peer-missing/quarantine` provide evidence-based KV repair and quarantine handling.
- `/replication/sql/export` and `/replication/sql/reconcile` provide the current SQL replication path.
- Host and replica roles are configurable with `TINYCLOUD_REPLICATION_ROLE`.
- Peer serving is configurable with `TINYCLOUD_REPLICATION_PEER_SERVING`.
- In TEE builds, `/attestation` and `/info.inTEE` expose attestation-related runtime signals.

### What the first production cut is actually rolling out

The first production cut should roll out:

- Authenticated replication sessions.
- Full auth sync between known peers.
- Conservative KV replication between known hosts and selected replicas.
- Static bootstrap and per-host fan-out registration.
- `/info` capability advertisement for routing and diagnostics.
- Optional TEE attestation validation for Phala-hosted canary instances.

The first production cut should not rely on:

- `/info` as a trust root.
- DHT or ambient peer discovery.
- Blind prune on absence.
- Automatic authority election.
- Broad replica peer-serving by default.

### Recommended first-cut scope

Roll out in this order:

- Auth sync and KV replication first.
- Host-to-host first.
- Host-to-replica second.
- Replica peer-serving only after the canary passes.
- SQL replication only behind an explicit canary gate, even though branch support exists.

## 2. Merge Order and Readiness Gates

### Merge order

1. Merge `tinycloud-node` replication branch to `main` with conservative defaults.
2. Merge the companion SDK and rollout automation changes after the node merge is accepted.
3. Publish a dedicated Phala-ready image for the replication rollout.
4. Apply canary deployment manifests and registration records.

### Runtime defaults at merge

Use safe defaults at merge time:

- `TINYCLOUD_REPLICATION_ROLE=host` unless the instance is explicitly a replica.
- `TINYCLOUD_REPLICATION_PEER_SERVING=false` unless the instance is explicitly approved to serve peers.
- `TINYCLOUD_REPLICATION_SESSION_TTL_SECS=600` unless operational tuning is justified.

### Readiness gates before merge

- Branch builds cleanly in CI for the production target image.
- The replication routes are covered by real end-to-end tests, not mocks.
- `/info`, `/replication/info`, `/replication/session/open`, auth sync, KV replay reconcile, and Recon compare/split flows are green in pre-merge test runs.
- The Phala image is built with the intended confidential-compute feature set.
- Monitoring, alerting, and log shipping are in place before the first canary instance is exposed.

### Readiness gates before canary

- A fixed bootstrap inventory exists for the canary spaces and peers.
- Host delegations and sync delegations are created for every canary participant.
- Attestation verification procedure is written down and tested.
- Each instance has isolated storage and a unique registration record.
- Rollback and drain commands are tested before customer traffic uses replication.

## 3. Phala Canary Topology

Use a small multi-instance canary, not a single-node smoke deploy.

### Recommended topology

- `tc-canary-a`: authority host for the canary spaces.
- `tc-canary-b`: secondary host for the same spaces.
- `tc-canary-r1`: replica with peer serving disabled.
- `tc-canary-r2`: replica reserved for peer-serving canary after the first gate passes.

### Placement guidance

- Put each instance on its own Phala CVM.
- Keep each instance on its own storage namespace.
- Keep the authority host on the most stable CVM and do not rotate authority during the first cut.
- Use the archived Phala deployment guidance as the baseline for image build, env encryption, and attestation handling.

### Canary phases

Phase 1:

- `tc-canary-a` and `tc-canary-b` only.
- Validate host-to-host auth sync and KV replication.

Phase 2:

- Add `tc-canary-r1`.
- Validate host-to-replica auth sync, replay reconcile, Recon compare, and quarantine behavior.

Phase 3:

- Add `tc-canary-r2` with peer serving enabled.
- Validate replica export only after the earlier phases are stable.

## 4. Registration Model

Registration must be treated as three separate layers.

### Infra registration

Infra registration says an instance exists as infrastructure.

It should include:

- Phala project or CVM identifier.
- deployment channel such as `canary` or `prod`.
- base URL and DNS record.
- image digest.
- attestation verification status.
- owner and on-call metadata.

Infra registration does not prove a space relationship. It only proves that an operator recognizes a concrete deployed instance.

### Instance registration

Instance registration says what a particular running instance claims it can do.

It should include:

- instance ID.
- base URL.
- replication role configured on the instance.
- whether peer serving is enabled.
- whether TEE mode is expected and verified.
- health and last-seen timestamps.
- storage backend identifiers.

`/info` belongs here. It is capability advertisement only. It is useful for:

- confirming the node supports replication.
- confirming the enabled role and peer-serving mode.
- confirming the service surface and software version.

`/info` is not a trust root and is not enough to authorize replication for a space.

### Space registration

Space registration is the trust-bearing layer.

It should include:

- the authority host for the space.
- all approved hosts for the space.
- all approved replicas for the space.
- the exact `tinycloud.space/host` and `tinycloud.space/sync` delegations used for those roles.
- peer-serving allowance for replicas, if any.
- the bootstrap host list for that space.

Space registration is where the rollout should rely on proof:

- `tinycloud.space/host` proves host authority for the space.
- `tinycloud.space/sync` proves replication scope for replicas.
- `/peer/generate/<space>` binds the serving node to its per-space server DID.
- `/attestation` proves the runtime identity of the instance if TEE validation is required.

### Registration rule for first production cut

- Infra registration is maintained by operations.
- Instance registration is maintained by deployment automation.
- Space registration is maintained by explicit host and sync delegations.
- Registration with hosts is per-host fan-out, not implicit cluster membership.

## 5. Bootstrap and Discovery Model

The first production cut should use static bootstrap and conservative discovery.

### First-contact bootstrap

For each canary space, maintain an explicit bootstrap record with:

- the authority host URL.
- the secondary host URL, if any.
- the approved replicas, if any.
- the expected server DID per host if already staged.

### Discovery order

1. Start from the explicit bootstrap host list for the space.
2. Call `/info` only to confirm capability advertisement and basic compatibility.
3. If the rollout requires TEE assurance, validate `/attestation`.
4. Resolve or stage the per-space server DID with `/peer/generate/<space>`.
5. Open `/replication/session/open` using the caller’s `tinycloud.space/sync` delegation.
6. Run auth sync before relying on data export from a first-contact peer.
7. Fan out registration to additional hosts explicitly, per host.

### Discovery rules

- Do not auto-discover new peers from `/info`.
- Do not use replica peer-serving as a bootstrap source in the first cut.
- Do not trust a host or replica for a space unless the matching host or sync delegation is already known or just synchronized through auth sync.

## 6. Storage Isolation Requirements

Every canary instance must have isolated mutable storage.

### Hard requirements

- No two instances may share the same SQLite database path.
- No two instances may share the same local block store directory.
- If Postgres is used, each instance must use a distinct database or schema.
- If object storage is used, each instance must use a distinct prefix or bucket namespace.
- Temporary directories, logs, and cache directories must be instance-scoped.

### Why this matters

The replication rollout is testing protocol behavior between nodes. Shared storage would hide real divergence, break forensic analysis, and turn replication bugs into storage corruption bugs.

### Recommended storage layout for canary

- one Postgres database or schema per instance.
- one block-storage prefix per instance.
- one Phala env file per instance.
- one monitoring identity per instance.

## 7. Canary Test Plan and Success Criteria

### Canary test plan

Run these tests in order:

- auth session open against every canary instance.
- auth sync from authority host to secondary host.
- auth sync from authority host to replica.
- KV host-to-host write, reconcile, and read validation.
- KV host-to-replica write, reconcile, and read validation.
- KV Recon compare and split on a diverged prefix.
- KV peer-missing quarantine path on a replica.
- restart one non-authority instance and confirm catch-up after restart.
- if SQL is in scope for the canary, run only on a dedicated canary space after KV is stable.

### Success criteria

- Zero unauthorized replication exports accepted.
- Zero cross-instance storage collisions.
- Auth sync converges on every canary instance.
- KV writes converge across the canary hosts and replicas within the expected polling window.
- Recon compare returns clean match after repair for the test prefixes.
- Quarantined keys remain hidden from canonical reads and visible only through the intended provisional path.
- No repeated crash loop, session leak, or auth-session invalidation bug appears during a 24-hour soak.
- Attestation verification succeeds for every instance that is expected to run in TEE mode.

### Exit criteria for widening rollout

- At least 24 hours of stable canary behavior.
- At least one controlled restart of a host and a replica with successful recovery.
- No unresolved auth, session, or storage-separation incidents.

## 8. Rollback and Drain Procedure

Rollback must preserve trust correctness first and traffic continuity second.

### Immediate drain

1. Remove the instance from the bootstrap inventory.
2. Stop issuing new space registrations to that instance.
3. Set `TINYCLOUD_REPLICATION_PEER_SERVING=false` on the draining instance.
4. Revoke the instance’s `tinycloud.space/sync` delegations if it should no longer replicate.
5. Wait for the replication session TTL window to expire or restart the instance to clear existing sessions.

### Host rollback

If a non-authority host is unhealthy:

- drain it from bootstrap and space registration.
- revoke its host delegation if it should no longer serve the space.
- leave the authority host unchanged.

If the authority host is unhealthy:

- do not promote a new authority automatically in the first cut.
- freeze new replication expansion.
- either roll back the authority host in place or perform a controlled manual authority reassignment with new host delegations.

### Replica rollback

- revoke the replica’s `tinycloud.space/sync` delegation.
- remove it from space registration and bootstrap lists.
- keep its storage for forensics until the incident is closed.

### Data handling rule

- Do not delete canary instance storage during initial rollback.
- Snapshot or preserve the instance state first so divergence can be inspected.

## 9. Open Questions and Deferred Items

### Open questions

- Whether SQL replication should be part of the first canary or delayed until the KV and auth planes soak cleanly.
- Whether replica peer-serving should require extra rollout policy beyond the existing sync delegation facts.
- How strict the attestation gate should be for non-TEE fallback environments.
- Whether a separate canonical-host registration record is needed operationally even though `tinycloud.space/host` is the proof.

### Deferred items

- Dynamic peer discovery.
- Any `/info`-driven automatic enrollment.
- Automatic authority election or failover.
- Merkle-proof-based auth sync.
- Blind prune-on-absence semantics.
- Broad production use of replica peer-serving before the host-host and host-replica lanes are stable.

## 10. Operational Checklist

Before merge:

- replication routes reviewed.
- production image built.
- dashboards and alerts ready.
- bootstrap inventory format finalized.

Before canary:

- host and sync delegations created.
- Phala instances deployed and attested.
- storage namespaces isolated.
- rollback rehearsal completed.

Before widening:

- canary soak passed.
- restart recovery passed.
- incident log reviewed.
- authority host remained stable throughout the canary window.
