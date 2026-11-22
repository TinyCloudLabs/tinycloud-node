/**
 * TC-3284: the deletion ledger's error events, each shipped individually with only its `error_kind`. The kinds are
 * exactly `DeletionLedgerError::kind()` (tinycloud-core/src/encryption_network/deletion_ledger.rs) and the canonical
 * schema's `error_kind` enum. Each event fires at most once per process, so they bypass caps and reducers.
 * `target` is the tracing target the node emits each event from; a line from any other target is not shipped as it.
 */
export const LEDGER_EVENTS = Object.freeze(['deletion_ledger_open_failed', 'deletion_ledger_replay_failed', 'deletion_ledger_unrepaired']);
export const LEDGER_TARGETS = Object.freeze({
  deletion_ledger_open_failed: 'tinycloud',
  deletion_ledger_replay_failed: 'tinycloud',
  deletion_ledger_unrepaired: 'tinycloud_core::encryption_network::deletion_ledger',
});
export const LEDGER_ERROR_KINDS = Object.freeze(['io', 'path', 'encode', 'moved', 'lock_held', 'malformed', 'refused', 'db']);
