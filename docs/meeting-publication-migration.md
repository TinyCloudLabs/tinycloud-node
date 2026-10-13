# Meeting publication rollback compatibility

Native meeting publication v3 has been withdrawn. Its activation, reservation, snapshot staging, publication, inspection, deletion, purge, and new-freeze commands return `publication_withdrawn` (HTTP 400). The core SQL actor independently rejects these commands, so bypassing HTTP admission cannot reactivate the protocol or mutate its catalog.

Ordinary SQL requests again use the standard SQL authorizer. Existing SQL capabilities, table/column restrictions, prepared-statement restrictions, and ancestor-chain constraints still apply. Authorized legacy clients can update `connector_meeting`; an authorized recovery operator can repair publication bookkeeping and remove the added schema through ordinary SQL and its durable artifact persistence.

The rollback binary does not automatically restore rows, remove publication schema, delete stored snapshots, or release existing write pauses. Those changes require a separately verified recovery of the affected space. Preserve the original private export and operation plan.

## Capabilities and retained controls

The existing `tinycloud.meetingPublication.v3` statement at the exact SQL path `xyz.tinycloud.tinychat/connectors` retains three commands: `capabilities`, `legacy_freeze_status`, and `unfreeze_legacy`. They require `tinycloud.sql/write` and the existing unconstrained ancestor-chain authority. Their SQL result has a `receipt` column containing one JSON string.

Capabilities report:

```json
{"contractVersion":3,"writerFencing":false,"snapshotImmutability":true,"digestVerification":false,"legacyWriteFreeze":false}
```

`snapshotImmutability` remains true because the KV protection for existing snapshot keys remains enforced. New snapshots cannot be created through the withdrawn publication protocol. `legacyWriteFreeze` is false because creating a new pause is no longer exposed.

Inspect a pre-existing pause:

```json
{"contractVersion":3,"operation":"legacy_freeze_status"}
```

A pause created by the previous binary may report:

```json
{"contractVersion":3,"legacyWritesFrozen":true,"legacyFreezeGeneration":1}
```

After restoring and verifying the affected catalog and original bodies, release the exact saved generation:

```json
{"contractVersion":3,"operation":"unfreeze_legacy","expectedGeneration":1}
```

Release reports `legacyWritesFrozen:false` and `legacyFreezeGeneration:2`. An immediate identical retry returns the same result. A stale generation fails with `legacy_freeze_generation_conflict` (HTTP 400); invalid generation inputs also return 400. Status and release remain available when content quota is exhausted and do not activate or alter the SQL catalog.

## Existing KV protections

An existing pause continues to block legacy writes under `xyz.tinycloud.tinychat/connectors/{fireflies,google-meet,tinycloud-transcriber}/` for:

- `transcript/…`
- `meeting/…`
- `archive-copy/transcript/…`

Reads, chat keys, cursors, credentials, and other spaces retain their existing behavior. Frozen ordinary KV put/delete returns HTTP 409. The core guard also rejects internal legacy cleanup. The pause survives a node restart; only an exact generation-checked release removes it.

The durable guard remains locked by protected KV mutation transactions through storage persistence and commit. PostgreSQL row locking and SQLite writer serialization retain their existing behavior. Failed guard reads fail closed. Existing snapshot keys remain protected after the legacy pause is released.

## Deployment compatibility

The central `meeting_legacy_write_guard` migration and its generation history remain registered. A pre-migration binary can reject startup when it sees an unknown applied migration, so reverting the container image alone is insufficient. Do not edit migration history or restore the shared database wholesale to recover one space.

Before deploying this withdrawal across shared infrastructure, identify every catalog that adopted publication v3 and coordinate its recovery and writers. Deploy the compatible binary to all traffic-serving instances. The legacy KV pause does not fence ordinary SQL after rollback, so keep application writers paused while restoring the catalog. Resume legacy writers only after verifying the restored rows and original bodies and releasing the saved KV pause.
