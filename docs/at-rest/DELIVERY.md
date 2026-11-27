# General content sealing delivery map

Checked against node `622e78cfc989134f6c38f2edebe98a9c8791ee89` on 2026-11-27.
This describes the existing integration work; it does not enable a storage mode
or assert a production rollout.

Sensitive metadata-column encryption is already wired separately through
`storage_keyrings` and `TinyCloud::new_with_encryption`. The general `at_rest`
module is not wired into authoritative KV/SQL storage at this commit.

| Existing PR | Work |
| --- | --- |
| [#628](https://github.com/TinyCloudLabs/tinycloud-node/pull/628) | Shared support crate |
| [#629](https://github.com/TinyCloudLabs/tinycloud-node/pull/629) | Keyring and key continuity |
| [#630](https://github.com/TinyCloudLabs/tinycloud-node/pull/630) | Runtime wiring |
| [#634](https://github.com/TinyCloudLabs/tinycloud-node/pull/634) | Block-storage plumbing |
| [#635](https://github.com/TinyCloudLabs/tinycloud-node/pull/635) | Filesystem blocks |
| [#636](https://github.com/TinyCloudLabs/tinycloud-node/pull/636) | S3 blocks |
| [#637](https://github.com/TinyCloudLabs/tinycloud-node/pull/637) | SQL/DuckDB artifacts |
| [#639](https://github.com/TinyCloudLabs/tinycloud-node/pull/639) | Deployment |

These were open drafts at the audit. Recheck their heads and dependency lists
when integrating; older references to #325–#327, #329, #333 and #336 are historical.
Continue the existing changes rather than creating another parallel implementation.

The integration needs a supported storage path with known payload writes,
ciphertext inspection of authoritative artifacts, key continuity across restart
and restore, rotation, legacy migration and rollback verification. These tests
are evidence for this capability, not prerequisites for unrelated application
or SDK work. Optional escrow choices should not silently become a new requirement
for an already authorized key source. Local caches/working files and deployment
configuration must be described separately from external artifact sealing.
