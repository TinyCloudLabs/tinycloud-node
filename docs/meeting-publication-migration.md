# Migrating legacy meeting artifacts

Native meeting publication v3 publishes immutable, digest-verified snapshots through the existing authenticated SQL service. Activation adds the connector publication schema and rejects generic writes to protected catalog tables. It does not verify or convert legacy bodies automatically.

A migration should inventory and validate the existing catalog and raw KV bodies, preserve a private copy and resumable operation plan, pause legacy artifact writes, activate the SQL fence, and revalidate the plan before publication. Verify every published copy before releasing the legacy KV pause. Keep the original capture extent and provenance unknown unless independently established.

## Temporary write barrier

These controls use the existing `tinycloud.meetingPublication.v3` statement at the exact SQL path `xyz.tinycloud.tinychat/connectors`. They require `tinycloud.sql/write` and the existing unconstrained ancestor-chain authority. Their SQL result has a `receipt` column containing one JSON string.

```json
{"contractVersion":3,"operation":"legacy_freeze_status"}
```

A fresh space reports:

```json
{"contractVersion":3,"legacyWritesFrozen":false,"legacyFreezeGeneration":0}
```

Persist the expected generation before issuing a control request:

```json
{"contractVersion":3,"operation":"freeze_legacy","expectedGeneration":0}
```

The successful receipt reports `legacyWritesFrozen:true` and `legacyFreezeGeneration:1`. After publication and verification, release that generation:

```json
{"contractVersion":3,"operation":"unfreeze_legacy","expectedGeneration":1}
```

Release reports `legacyWritesFrozen:false` and `legacyFreezeGeneration:2`. Each actual transition increments the generation. An immediate identical retry returns the same result; a stale request from an older cycle fails with `legacy_freeze_generation_conflict` (HTTP 400). Invalid generation inputs also return 400. Generations distinguish migration cycles, not independent operators issuing identical simultaneous requests; coordinate one operator per migration.

The native route advertises `legacyWriteFreeze:true` in its publication capabilities. Status, freeze and release remain available when content quota is exhausted; content-growing publication operations remain quota checked.

## Protected scope and guarantees

The pause applies only to these paths under `xyz.tinycloud.tinychat/connectors/{fireflies,google-meet,tinycloud-transcriber}/`:

- `transcript/…`
- `meeting/…`
- `archive-copy/transcript/…`

Reads, chat keys, cursors, credentials, other spaces and native snapshot publication remain available. Frozen ordinary KV put/delete returns HTTP 409. Frozen native delete/purge returns HTTP 403 before known catalog mutation. The core guard also rejects internal legacy cleanup.

The durable guard is locked by the protected KV mutation transaction before its first database read. PostgreSQL row locking and SQLite writer serialization hold that lock through storage persistence and commit. A freeze acknowledgement therefore drains earlier protected KV commits. Failed guard reads fail closed, and restarting the node does not release a pause.

The early native delete/purge check does not make the separate SQL publication and KV cleanup transactions globally atomic across multiple instances. Deploy compatible code to every traffic-serving node and coordinate migration writers. Freeze alone does not fence generic SQL; activation supplies that separate catalog fence.

Release allows later legacy artifact mutations. It does not deactivate the SQL fence or weaken immutable snapshots, which retain the verified original body independently. Older writers cannot publish to an activated catalog and should be replaced by compatible clients.

## Rollout and recovery

The central `meeting_legacy_write_guard` migration creates the table without automatically freezing a space. Old binaries that do not recognize its migration name may reject startup against the upgraded database. Its down operation refuses to silently discard the guard generation. A rollback build must recognize the migration; after catalog activation it must also retain the publication protocol and writer fences.

Keep a compatible node running for inspection, repair and resume. Retain the original private plan and operation IDs after interruption or a lost acknowledgement. Do not invent new operations to recover uncertain publications, edit migration history, or restore a shared database wholesale to recover one space.
