//! TC-2917: what a client sees when a DuckDB write races another checkpoint
//! replacement. The refusal leaves the `/invoke` DuckDB route through the
//! same mapping as the route's own (`duckdb_error_to_status` plus the error
//! text as the body) and the node's real `Retry-After` fairing: a `503`
//! whose body starts with `unavailable_retryable: `, with `Retry-After: 1`,
//! exactly like SQL's replacement-busy refusal.

use rocket::{get, http::Status, local::asynchronous::Client, routes};
use tinycloud_core::{duckdb::DuckDbError, sql::SqlError};

use super::{duckdb_error_to_status, sql_error_to_status, InvokeError};

fn as_route_error(status: Status, message: String) -> Result<(), InvokeError> {
    Err((status, message).into())
}

#[get("/duckdb-replacement-busy")]
fn duckdb_replacement_busy() -> Result<(), InvokeError> {
    let error = DuckDbError::Unavailable;
    as_route_error(duckdb_error_to_status(&error), error.to_string())
}

#[get("/sql-replacement-busy")]
fn sql_replacement_busy() -> Result<(), InvokeError> {
    let error = SqlError::ReplacementBusy;
    as_route_error(sql_error_to_status(&error), error.to_string())
}

#[tokio::test]
async fn duckdb_replacement_busy_is_a_retryable_503_like_sql() {
    let client = Client::tracked(
        rocket::build()
            .mount("/", routes![duckdb_replacement_busy, sql_replacement_busy])
            .attach(crate::retry_after_fairing()),
    )
    .await
    .expect("valid Rocket instance");

    for path in ["/duckdb-replacement-busy", "/sql-replacement-busy"] {
        let response = client.get(path).dispatch().await;
        assert_eq!(response.status(), Status::ServiceUnavailable, "{path}");
        assert_eq!(
            response.headers().get_one("Retry-After"),
            Some("1"),
            "{path}"
        );
        let body = response.into_string().await.unwrap();
        assert!(
            body.starts_with("unavailable_retryable: "),
            "{path}: {body}"
        );
    }
}
