//! Data-free description of a database failure that ends a request in a 5xx
//! (TC-1796).
//!
//! The failing layer records a [`FailureNote`] on the request
//! ([`crate::request_telemetry::note_failure`]); the node's tracing fairing
//! turns it into one log line when the response is sent. A note holds only
//! fixed vocabulary (a [`Service`], a [`FailureCode`], a [`failure_kind`]) and
//! a [`db_ref`] hash. It never holds an error message, SQL, a space id or a
//! database name.

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
    /// [`db_ref`], when the failing layer knows which database it was using.
    pub db_ref: Option<String>,
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
            SqlxError::Io(_) => "io",
            SqlxError::Database(database) => match database.code().as_deref() {
                Some("57014") => "statement_timeout",
                Some("40001" | "40P01") => "serialization",
                _ if is_connection_error(error) => "connection_lost",
                _ => "other",
            },
            _ if is_connection_error(error) => "connection_lost",
            _ => "other",
        },
        _ => "other",
    }
}

/// A short stable reference to a database: the first 8 bytes of
/// `BLAKE3("tc-diag-db-v1" || space id || "/" || database name)`, as 16
/// lowercase hex characters. It lets two log lines be matched to the same
/// database without naming it.
pub fn db_ref(space: &str, db_name: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"tc-diag-db-v1");
    hasher.update(space.as_bytes());
    hasher.update(b"/");
    hasher.update(db_name.as_bytes());
    hex::encode(&hasher.finalize().as_bytes()[..8])
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
    fn db_ref_is_a_stable_16_hex_hash_of_the_space_and_database() {
        let space = "tinycloud:pkh:eip155:1:0xAbC0000000000000000000000000000000000001:default";
        let reference = db_ref(space, "notes.db");
        assert_eq!(reference, db_ref(space, "notes.db"), "stable");
        assert_eq!(reference.len(), 16);
        assert!(
            reference
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "{reference}"
        );
        assert_ne!(reference, db_ref(space, "other.db"), "differs per database");
        assert_ne!(
            reference,
            db_ref(
                "tinycloud:pkh:eip155:1:0xAbC0000000000000000000000000000000000002:default",
                "notes.db"
            ),
            "differs per space"
        );
        assert!(!space.contains(&reference) && !reference.contains("notes"));
        // The documented construction, not merely some hash.
        let expected = blake3::hash(format!("tc-diag-db-v1{space}/notes.db").as_bytes());
        assert_eq!(reference, hex::encode(&expected.as_bytes()[..8]));
    }
}
