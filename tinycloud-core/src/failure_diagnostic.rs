//! Data-free description of a database failure that ends a request in a 5xx
//! (TC-1796).
//!
//! The failing layer records a [`FailureNote`] on the request
//! ([`crate::request_telemetry::note_failure`]); the node's tracing fairing
//! turns it into one log line when the response is sent. A note holds only
//! fixed vocabulary (a [`Service`], a [`FailureCode`], a [`failure_kind`]) and
//! a keyed database pseudonym. It never holds an error message, SQL, a space
//! id or a database name.

use sea_orm::{
    error::{ConnAcquireErr, RuntimeErr, SqlxError},
    DbErr,
};

use crate::db_pool::is_connection_error;

/// Which service the failed request belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Service {
    Sql,
    Duckdb,
    Kv,
    Other,
}

impl Service {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sql => "sql",
            Self::Duckdb => "duckdb",
            Self::Kv => "kv",
            Self::Other => "other",
        }
    }
}

/// How the node answered the failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureCode {
    /// `503`: no write can have taken effect.
    UnavailableRetryable,
    /// `500`: a write may have been applied.
    OutcomeUnknown,
    /// `500`: any other database failure.
    Internal,
    /// `503`: a bounded wait or the request deadline ended before any write
    /// began (or, once [`crate::request_telemetry::note_outcome_unknown`]
    /// applies, `500` [`FailureCode::OutcomeUnknown`]).
    Busy,
}

/// What the failing layer knows about the failure. See the module docs for
/// what it never holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailureNote {
    pub service: Service,
    pub code: FailureCode,
    /// One of the fixed strings of [`failure_kind`].
    pub kind: &'static str,
    pub write_may_have_applied: bool,
    /// The keyed pseudonym of the database in use (64 lowercase hex digits,
    /// [`crate::telemetry::Pseudonymizer::db_hash`]), when the failing layer
    /// knows it.
    pub db_hash: Option<String>,
}

/// [`FailureNote::kind`] of a request that reached its deadline.
pub const KIND_REQUEST_TIMEOUT: &str = "request_timeout";
/// [`FailureNote::kind`] of a read whose audit record was not confirmed in
/// time.
pub const KIND_READ_AUDIT_BUSY: &str = "read_audit_busy";
/// [`failure_kind`] of a lost connection that is not an `io` error.
pub const KIND_CONNECTION_LOST: &str = "connection_lost";
/// [`failure_kind`] of a socket error (reset, timeout, broken pipe).
pub const KIND_IO: &str = "io";

impl FailureNote {
    /// A wait that gave up with `503` before any write began. `kind` is a
    /// [`SqlBusyStage`](crate::sql::SqlBusyStage) name (`lock_wait`,
    /// `hydration`, `artifact_transfer`), [`KIND_REQUEST_TIMEOUT`] or
    /// [`KIND_READ_AUDIT_BUSY`].
    pub fn busy(service: Service, kind: &'static str, db_hash: Option<String>) -> Self {
        Self {
            service,
            code: FailureCode::Busy,
            kind,
            write_may_have_applied: false,
            db_hash,
        }
    }

    /// A failure that is not a database error, answered `500`.
    pub fn internal(service: Service) -> Self {
        Self {
            service,
            code: FailureCode::Internal,
            kind: "other",
            write_may_have_applied: false,
            db_hash: None,
        }
    }
}

/// The longest [`ErrorCode::as_str`], in bytes. The log shipper's capped
/// 5xx reserve (TC-1843) fits a code of at most this length under either
/// sink framing (`log-shipper/budget.mjs`).
pub const MAX_ERROR_CODE_LEN: usize = 13;

/// The stable code a request answered with a 5xx carries on its
/// `node_request` event as `error_code` (TC-3834): one per origin of a 5xx,
/// so two failures that read alike in the client's body stay apart in the
/// logs. The set is closed; a value is only ever one of [`ErrorCode::ALL`]'s
/// strings (snake_case ASCII, at most [`MAX_ERROR_CODE_LEN`] bytes), never
/// text taken from the error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    /// A database error other than a timeout (SeaORM/sqlx: a lost
    /// connection, a refused or failed statement, a serialization failure).
    DbError,
    /// A database timeout: the pool gave no connection in time (or was
    /// closed), or the server cancelled the statement at its timeout.
    DbTimeout,
    /// The SQL/DuckDB database stayed busy past a wait bound (`sql_busy`).
    DbBusy,
    /// The `/invoke` deadline was reached before any write began.
    ReqTimeout,
    /// A read's audit record was not confirmed (busy, unavailable, failed
    /// or stopped).
    ReadAudit,
    /// The block store failed to stage, write or read a blob.
    StorageIo,
    /// The database read of a delegation chain's SQL caveats failed
    /// (`ChainCaveatError::Db`).
    CaveatDb,
    /// No read transaction could be opened (`TinyCloud::readable`).
    ReadTxError,
    /// The encryption-key deletion ledger is missing or its append failed.
    KeyLedger,
    /// The space lifecycle state could not be read.
    Lifecycle,
    /// The delegation registry could not be consulted.
    RegistryDown,
    /// An SQL/DuckDB identity cutover fence is active.
    CutoverFence,
    /// A KV blob candidate could not be committed.
    KvCandidate,
    /// The SQL or DuckDB engine failed for a reason other than its database
    /// connection (an internal, ingest, import or export error).
    EngineError,
    /// The encryption backend or signer failed, or a key row is corrupt.
    Encryption,
    /// A database refused to grow past, or load beyond, its size limit
    /// (`507`).
    SizeLimit,
    /// The node's disk is below its free-space headroom (`507`).
    DiskHeadroom,
    /// Any other 5xx, including one no origin classified.
    Internal,
}

impl ErrorCode {
    /// Every code, for consumers that hold the closed set (the log
    /// shipper's schema, tests).
    pub const ALL: [ErrorCode; 18] = [
        Self::DbError,
        Self::DbTimeout,
        Self::DbBusy,
        Self::ReqTimeout,
        Self::ReadAudit,
        Self::StorageIo,
        Self::CaveatDb,
        Self::ReadTxError,
        Self::KeyLedger,
        Self::Lifecycle,
        Self::RegistryDown,
        Self::CutoverFence,
        Self::KvCandidate,
        Self::EngineError,
        Self::Encryption,
        Self::SizeLimit,
        Self::DiskHeadroom,
        Self::Internal,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::DbError => "db_error",
            Self::DbTimeout => "db_timeout",
            Self::DbBusy => "db_busy",
            Self::ReqTimeout => "req_timeout",
            Self::ReadAudit => "read_audit",
            Self::StorageIo => "storage_io",
            Self::CaveatDb => "caveat_db",
            Self::ReadTxError => "read_tx_error",
            Self::KeyLedger => "key_ledger",
            Self::Lifecycle => "lifecycle",
            Self::RegistryDown => "registry_down",
            Self::CutoverFence => "cutover_fence",
            Self::KvCandidate => "kv_candidate",
            Self::EngineError => "engine_error",
            Self::Encryption => "encryption",
            Self::SizeLimit => "size_limit",
            Self::DiskHeadroom => "disk_headroom",
            Self::Internal => "internal",
        }
    }

    /// The class of a database error: [`ErrorCode::DbTimeout`] for a pool
    /// that gave no connection or a statement the server timed out,
    /// [`ErrorCode::DbError`] otherwise.
    pub fn for_db(error: &DbErr) -> Self {
        Self::for_kind(failure_kind(error))
    }

    /// The code of a recorded [`FailureNote`].
    pub fn for_note(note: &FailureNote) -> Self {
        match (note.code, note.kind) {
            (_, KIND_REQUEST_TIMEOUT) => Self::ReqTimeout,
            (FailureCode::Busy, KIND_READ_AUDIT_BUSY) => Self::ReadAudit,
            (FailureCode::Busy, _) => Self::DbBusy,
            // `FailureNote::internal`: not a database error.
            (FailureCode::Internal, _) => Self::Internal,
            (FailureCode::UnavailableRetryable | FailureCode::OutcomeUnknown, kind) => {
                Self::for_kind(kind)
            }
        }
    }

    fn for_kind(kind: &str) -> Self {
        match kind {
            "pool_timeout" | "pool_closed" | "statement_timeout" => Self::DbTimeout,
            _ => Self::DbError,
        }
    }
}

/// A fixed class of a database failure, from the error's variant and, for a
/// server error, its SQLSTATE. Never any text of the error.
pub fn failure_kind(error: &DbErr) -> &'static str {
    match error {
        DbErr::ConnectionAcquire(ConnAcquireErr::Timeout) => "pool_timeout",
        DbErr::ConnectionAcquire(ConnAcquireErr::ConnectionClosed) => "pool_closed",
        DbErr::Conn(RuntimeErr::SqlxError(sqlx))
        | DbErr::Exec(RuntimeErr::SqlxError(sqlx))
        | DbErr::Query(RuntimeErr::SqlxError(sqlx)) => match sqlx {
            SqlxError::PoolTimedOut => "pool_timeout",
            SqlxError::PoolClosed => "pool_closed",
            SqlxError::Io(_) => KIND_IO,
            SqlxError::Database(database) => match database.code().as_deref() {
                Some("57014") => "statement_timeout",
                Some("40001" | "40P01") => "serialization",
                _ if is_connection_error(error) => KIND_CONNECTION_LOST,
                _ => "other",
            },
            _ if is_connection_error(error) => KIND_CONNECTION_LOST,
            _ => "other",
        },
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{borrow::Cow, error::Error as StdError, fmt, io};

    #[derive(Debug)]
    struct FakeDatabaseError(&'static str);

    impl fmt::Display for FakeDatabaseError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "secret statement text {}", self.0)
        }
    }

    impl StdError for FakeDatabaseError {}

    impl sea_orm::sqlx::error::DatabaseError for FakeDatabaseError {
        fn message(&self) -> &str {
            "secret statement text"
        }

        fn code(&self) -> Option<Cow<'_, str>> {
            Some(Cow::Borrowed(self.0))
        }

        fn as_error(&self) -> &(dyn StdError + Send + Sync + 'static) {
            self
        }

        fn as_error_mut(&mut self) -> &mut (dyn StdError + Send + Sync + 'static) {
            self
        }

        fn into_error(self: Box<Self>) -> Box<dyn StdError + Send + Sync + 'static> {
            self
        }

        fn kind(&self) -> sea_orm::sqlx::error::ErrorKind {
            sea_orm::sqlx::error::ErrorKind::Other
        }
    }

    fn server_error(sqlstate: &'static str) -> DbErr {
        DbErr::Exec(RuntimeErr::SqlxError(SqlxError::Database(Box::new(
            FakeDatabaseError(sqlstate),
        ))))
    }

    #[test]
    fn failure_kind_is_a_fixed_class_per_variant_and_sqlstate() {
        let cases = [
            (
                DbErr::ConnectionAcquire(ConnAcquireErr::Timeout),
                "pool_timeout",
            ),
            (
                DbErr::Conn(RuntimeErr::SqlxError(SqlxError::PoolTimedOut)),
                "pool_timeout",
            ),
            (
                DbErr::ConnectionAcquire(ConnAcquireErr::ConnectionClosed),
                "pool_closed",
            ),
            (
                DbErr::Query(RuntimeErr::SqlxError(SqlxError::Io(io::Error::other(
                    "peer address 10.0.0.1 reset",
                )))),
                "io",
            ),
            (
                DbErr::Query(RuntimeErr::SqlxError(SqlxError::WorkerCrashed)),
                "connection_lost",
            ),
            (server_error("57P01"), "connection_lost"),
            (server_error("08006"), "connection_lost"),
            (server_error("57014"), "statement_timeout"),
            (server_error("40001"), "serialization"),
            (server_error("40P01"), "serialization"),
            (server_error("23505"), "other"),
            (DbErr::Custom("relation \"secret\" missing".into()), "other"),
            (DbErr::RecordNotFound("secret".into()), "other"),
        ];
        for (error, expected) in cases {
            assert_eq!(failure_kind(&error), expected, "{error:?}");
        }
    }

    #[test]
    fn db_hash_is_the_requests_keyed_pseudonym_and_never_holds_its_inputs() {
        use crate::{
            keys::StaticSecret,
            request_telemetry::{self, RequestContext},
            telemetry::Pseudonymizer,
        };
        use std::sync::Arc;

        let pseudonymizer = Arc::new(Pseudonymizer::new(
            &StaticSecret::new(vec![0x42; 32]).unwrap(),
        ));
        let space: tinycloud_auth::resource::SpaceId =
            "tinycloud:pkh:eip155:1:0x1234567890123456789012345678901234567890:default"
                .parse()
                .unwrap();
        let other_space: tinycloud_auth::resource::SpaceId =
            "tinycloud:pkh:eip155:1:0x1234567890123456789012345678901234567890:other"
                .parse()
                .unwrap();

        assert_eq!(request_telemetry::db_hash("sql", &space, "notes.db"), None);

        let _request = request_telemetry::enter(Some(RequestContext::new(
            uuid::Uuid::nil(),
            Arc::clone(&pseudonymizer),
        )));
        let hash = request_telemetry::db_hash("sql", &space, "notes.db").unwrap();
        let expected = pseudonymizer.db_hash("sql", &space, "notes.db").unwrap();
        assert_eq!(hash, hex::encode(expected.into_bytes()));
        assert_eq!(hash.len(), 64);
        assert!(hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        for input in [
            "notes.db",
            "default",
            "1234567890123456789012345678901234567890",
        ] {
            assert!(!hash.contains(input), "{input}");
        }
        assert_ne!(
            Some(&hash),
            request_telemetry::db_hash("sql", &space, "x.db").as_ref()
        );
        assert_ne!(
            Some(&hash),
            request_telemetry::db_hash("sql", &other_space, "notes.db").as_ref()
        );
    }

    #[test]
    fn an_unknown_outcome_upgrades_or_creates_the_note_and_a_later_note_replaces_it() {
        use crate::{
            keys::StaticSecret, request_telemetry::RequestContext, telemetry::Pseudonymizer,
        };
        use std::sync::Arc;

        let new_request = || {
            RequestContext::new(
                uuid::Uuid::nil(),
                Arc::new(Pseudonymizer::new(
                    &StaticSecret::new(vec![0x42; 32]).unwrap(),
                )),
            )
        };

        // After a busy wait: the kind and database stay, the code changes.
        let request = new_request();
        request.note_failure(FailureNote::busy(
            Service::Sql,
            "artifact_transfer",
            Some("hash".into()),
        ));
        request.note_outcome_unknown(Service::Other, None);
        assert_eq!(
            request.failure(),
            Some(FailureNote {
                service: Service::Sql,
                code: FailureCode::OutcomeUnknown,
                kind: "artifact_transfer",
                write_may_have_applied: true,
                db_hash: Some("hash".into()),
            })
        );

        // With no earlier note: one is created from what the caller knows.
        let request = new_request();
        assert_eq!(request.failure(), None);
        request.note_outcome_unknown(Service::Sql, Some("hash".into()));
        assert_eq!(
            request.failure(),
            Some(FailureNote {
                service: Service::Sql,
                code: FailureCode::OutcomeUnknown,
                kind: "other",
                write_may_have_applied: true,
                db_hash: Some("hash".into()),
            })
        );

        // The last failure recorded is the one reported.
        request.note_failure(FailureNote::internal(Service::Kv));
        assert_eq!(request.failure(), Some(FailureNote::internal(Service::Kv)));
    }

    #[test]
    fn error_codes_are_a_closed_set_of_distinct_snake_case_strings() {
        let codes: Vec<&str> = ErrorCode::ALL.iter().map(|code| code.as_str()).collect();
        for code in &codes {
            assert!(
                !code.is_empty()
                    && code.len() <= MAX_ERROR_CODE_LEN
                    && code.starts_with(|c: char| c.is_ascii_lowercase())
                    && code
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "{code}"
            );
        }
        let mut distinct = codes.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), codes.len(), "{codes:?}");
        assert!(codes.contains(&"internal"));
    }

    #[test]
    fn error_codes_classify_database_failures_and_notes() {
        assert_eq!(
            ErrorCode::for_db(&DbErr::ConnectionAcquire(ConnAcquireErr::Timeout)),
            ErrorCode::DbTimeout
        );
        assert_eq!(
            ErrorCode::for_db(&DbErr::ConnectionAcquire(ConnAcquireErr::ConnectionClosed)),
            ErrorCode::DbTimeout
        );
        assert_eq!(
            ErrorCode::for_db(&server_error("57014")),
            ErrorCode::DbTimeout
        );
        assert_eq!(
            ErrorCode::for_db(&server_error("40001")),
            ErrorCode::DbError
        );
        assert_eq!(
            ErrorCode::for_db(&DbErr::Custom("secret".into())),
            ErrorCode::DbError
        );
        let busy = |kind| FailureNote::busy(Service::Sql, kind, None);
        assert_eq!(
            ErrorCode::for_note(&busy(KIND_REQUEST_TIMEOUT)),
            ErrorCode::ReqTimeout
        );
        assert_eq!(
            ErrorCode::for_note(&busy(KIND_READ_AUDIT_BUSY)),
            ErrorCode::ReadAudit
        );
        assert_eq!(ErrorCode::for_note(&busy("lock_wait")), ErrorCode::DbBusy);
        assert_eq!(
            ErrorCode::for_note(&FailureNote::internal(Service::Sql)),
            ErrorCode::Internal
        );

        // The request keeps the code of its last recorded failure.
        let request = crate::request_telemetry::RequestContext::new(
            uuid::Uuid::nil(),
            std::sync::Arc::new(crate::telemetry::Pseudonymizer::new(
                &crate::keys::StaticSecret::new(vec![0x42; 32]).unwrap(),
            )),
        );
        assert_eq!(request.error_code(), None);
        request.note_failure(busy("lock_wait"));
        assert_eq!(request.error_code(), Some(ErrorCode::DbBusy));
        request.note_outcome_unknown(Service::Sql, None);
        assert_eq!(request.error_code(), Some(ErrorCode::DbError));
        request.note_error_code(ErrorCode::CaveatDb);
        assert_eq!(request.error_code(), Some(ErrorCode::CaveatDb));
    }
}
