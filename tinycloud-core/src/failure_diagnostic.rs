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
}
