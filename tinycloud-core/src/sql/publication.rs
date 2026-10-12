//! Compatibility surface for the withdrawn TinyChat publication protocol.
//!
//! Existing snapshot keys stay immutable. Publication mutations are unavailable;
//! ordinary SQL authorization controls the legacy catalog again.
use super::types::SqlError;
use rusqlite::Connection;
use serde_json::{json, Value};

pub const STATEMENT: &str = "tinycloud.meetingPublication.v3";
pub const DATABASE: &str = "connectors";
pub const SQL_PATH: &str = "xyz.tinycloud.tinychat/connectors";
pub const ENVELOPE_LIMIT: usize = 2_097_152;

pub fn connector_owned_path(path: &str) -> bool {
    path.strip_prefix(&format!("{SQL_PATH}/"))
        .is_some_and(|tail| {
            matches!(
                tail.split('/').next(),
                Some("fireflies" | "google-meet" | "tinycloud-transcriber")
            )
        })
}
pub fn protected_snapshot_path(path: &str) -> bool {
    path.strip_prefix(&format!("{SQL_PATH}/"))
        .is_some_and(|tail| tail.split('/').nth(1) == Some("snapshot"))
}

/// Keep the actor entry point read-only even when called without HTTP admission.
pub fn execute(_conn: &Connection, _space: &str, command: &Value) -> Result<Value, SqlError> {
    if command["contractVersion"] != 3 || command["operation"].as_str().is_none() {
        return Err(SqlError::InvalidStatement(
            "publication_invalid_command".into(),
        ));
    }
    if command["operation"] == "capabilities" {
        return Ok(json!({
            "contractVersion": 3,
            "writerFencing": false,
            "snapshotImmutability": true,
            "digestVerification": false
        }));
    }
    Err(SqlError::InvalidStatement("publication_withdrawn".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn publication_rollback_rejects_commands_without_creating_schema() {
        let conn = Connection::open_in_memory().unwrap();
        for operation in [
            "activate",
            "reserve",
            "prepare_stage",
            "stage",
            "publish",
            "inspect",
            "delete",
            "purge",
            "freeze_legacy",
        ] {
            let error = execute(
                &conn,
                "space",
                &json!({"contractVersion":3,"operation":operation}),
            )
            .expect_err("withdrawn publication command accepted");
            assert!(
                error.to_string().contains("publication_withdrawn"),
                "{operation}: {error}"
            );
            assert_eq!(
                conn.query_row("SELECT COUNT(*) FROM sqlite_master", [], |row| row
                    .get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
        let caps = execute(
            &conn,
            "space",
            &json!({"contractVersion":3,"operation":"capabilities"}),
        )
        .unwrap();
        assert_eq!(caps["writerFencing"], false);
        assert_eq!(caps["digestVerification"], false);
        assert_eq!(caps["snapshotImmutability"], true);
    }
}
