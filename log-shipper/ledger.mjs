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
/**
 * TC-4177: the one line the node logs per start, after the ledger replay (`log_deletion_ledger_start`,
 * tinycloud-node-server/src/lib.rs, target `tinycloud`, info). It ships as an individual event carrying only the file
 * state, five bounded counts and the newest `deletedAt` (or `none`); the failure variant carries only `error_kind`.
 * `ledger_file` is exactly `LedgerFileState::as_str()`. The event fires once per process: no cap or reducer.
 */
export const LEDGER_START_EVENT = 'deletion_ledger_start';
export const LEDGER_START_TARGET = 'tinycloud';
export const LEDGER_START_MESSAGE = 'deletion ledger at start';
export const LEDGER_START_FAILED_MESSAGE = 'deletion ledger counts unavailable at start';
export const LEDGER_START_FILES = Object.freeze(['missing', 'empty', 'present']);
export const LEDGER_START_COUNTERS = Object.freeze(['bytes', 'operations', 'key_entries', 'committed', 'aborted']);
