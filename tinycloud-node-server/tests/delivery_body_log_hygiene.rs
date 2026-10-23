//! A delivery authorization body holds a link, and the link's fragment holds
//! its key. Rocket's `Json` guard prints the whole request body in its
//! failure log; the delivery route's own guard must not.
//!
//! This test owns its process: it installs the `log` to `tracing` bridge the
//! node installs at start and captures everything Rocket logs while it
//! refuses malformed bodies. The control route uses Rocket's `Json` guard to
//! show the capture sees such a log line.

use parking_lot::Mutex;
use rocket::{
    config::LogLevel,
    http::{ContentType, Status},
    local::asynchronous::Client,
    post, routes,
    serde::json::Json,
};
use std::sync::Arc;
use tinycloud::policy_v3::{DeliveryAuthorizationRequest, DeliveryBody};

const KEY: &str = "SENTINELKEYSENTINELKEYSENTINELKEYSENTINELKE";

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = Captured;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[post("/guarded", format = "json", data = "<body>")]
fn guarded(body: DeliveryBody) -> &'static str {
    let _ = body.0;
    "ok"
}

#[post("/control", format = "json", data = "<_body>")]
fn control(_body: Json<DeliveryAuthorizationRequest>) -> &'static str {
    "ok"
}

fn body(extra: &str) -> String {
    format!(
        r#"{{"shareUrl":"https://share.tinycloud.xyz/s/lqdw5iopqq2tkkvjj6gbbi5vbv#v=4&k={KEY}&c=bafkreiewixmt5nwgi3ych6durcsheaql3ybswbplpjmpbdhfkvdkidzt5u","recipientEmail":"a@example.com","documentName":"d","jti":"AAAAAAAAAAAAAAAAAAAAAA","expiresAt":"2026-10-24T12:00:00Z","requestBodyDigest":"x"{extra}}}"#
    )
}

#[tokio::test]
async fn the_delivery_guard_never_logs_the_body() {
    let captured = Captured::default();
    tracing_log::LogTracer::init().expect("this test binary owns the log facade");
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(captured.clone())
            .with_max_level(tracing::Level::TRACE)
            .finish(),
    )
    .expect("this test binary owns the global subscriber");

    let figment = rocket::Config::figment().merge(("log_level", LogLevel::Debug));
    let client = Client::tracked(rocket::custom(figment).mount("/", routes![guarded, control]))
        .await
        .unwrap();
    let post = |path: &'static str, text: String| {
        client
            .post(path)
            .header(ContentType::JSON)
            .body(text)
            .dispatch()
    };

    // The control: Rocket's own guard logs the body it refused, key included.
    let response = post("/control", body(r#","envelopeKey":"x""#)).await;
    assert_eq!(response.status(), Status::UnprocessableEntity);
    assert!(
        String::from_utf8_lossy(&captured.0.lock()).contains(KEY),
        "the capture sees Rocket's failure log"
    );
    captured.0.lock().clear();

    // The delivery guard: same statuses, nothing in the log, nothing in the answer.
    let accepted = post("/guarded", body("")).await;
    assert_eq!(accepted.status(), Status::Ok);
    for (label, text, expected) in [
        (
            "unknown field",
            body(r#","envelopeKey":"x""#),
            Status::UnprocessableEntity,
        ),
        (
            "removed fields",
            body(r#","envelope":{},"sealedEnvelope":"AAAA","shareCid":"c""#),
            Status::UnprocessableEntity,
        ),
        (
            "wrong type",
            body("").replace(r#""documentName":"d""#, r#""documentName":5"#),
            Status::UnprocessableEntity,
        ),
        (
            "missing field",
            body("").replace(r#""jti":"AAAAAAAAAAAAAAAAAAAAAA","#, ""),
            Status::UnprocessableEntity,
        ),
        ("not json", format!("{{{KEY} not json"), Status::BadRequest),
        ("truncated", body("")[..80].to_owned(), Status::BadRequest),
        (
            "over the limit",
            format!("{}{KEY}", " ".repeat(1_100_000)),
            Status::PayloadTooLarge,
        ),
    ] {
        let response = post("/guarded", text).await;
        assert_eq!(response.status(), expected, "{label}");
        let answer = response.into_string().await.unwrap_or_default();
        assert!(!answer.contains(KEY), "{label}: the answer holds the key");
    }
    let log = String::from_utf8_lossy(&captured.0.lock()).into_owned();
    assert!(!log.contains(KEY), "the log holds the key");
    assert!(!log.contains("#v=4"), "the log holds a link fragment");
    assert!(
        log.contains("DeliveryBody"),
        "the refusals were logged, by name only"
    );
}
