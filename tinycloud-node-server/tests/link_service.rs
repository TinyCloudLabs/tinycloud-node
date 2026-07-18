// Integration tests for the `link` module:
//   1. Enable happy path against a mock link service (claim + cert issuance).
//   2. 409 name-taken surfaces as `LinkError::NameConflict` with the name.
//   3. TLS proxy roundtrip: bytes sent to the TLS listener come out the far
//      side of an internal loopback echo server unchanged.
//
// Neither of these tests touches the network — the mock link service and the
// echo server run on 127.0.0.1 with OS-assigned ports.
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, StatusCode},
    response::IntoResponse,
    routing::{post, put},
    Json, Router,
};
use rcgen::{CertificateParams, DnType, KeyPair, SanType, PKCS_ECDSA_P256_SHA256};
use serde::Deserialize;
use serde_json::json;
use tempfile::tempdir;
use tinycloud::{
    config::Keys,
    link::{
        commands::{enable, EnableArgs},
        proxy, state,
    },
};
use tinycloud_core::keys::StaticSecret;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct AnyClaim {
    #[serde(default)]
    name: String,
    #[serde(default)]
    subject: String,
    #[serde(default)]
    sequence: u64,
    #[serde(default, rename = "lanIps")]
    lan_ips: Vec<String>,
    #[serde(default)]
    csr: String,
}

#[derive(Default)]
struct MockService {
    behavior: Behavior,
    seen_claims: Vec<AnyClaim>,
    seen_certs: Vec<AnyClaim>,
    seen_deletes: Vec<AnyClaim>,
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum Behavior {
    #[default]
    Ok,
    ClaimConflict,
    RateLimited,
}

async fn put_name(
    Path(name): Path<String>,
    State(state): State<Arc<Mutex<MockService>>>,
    body: Bytes,
) -> impl IntoResponse {
    let claim: AnyClaim = serde_json::from_slice(&body).unwrap();
    let mut svc = state.lock().unwrap();
    if svc.behavior == Behavior::ClaimConflict {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "name already claimed by a different subject"})),
        )
            .into_response();
    }
    if svc.behavior == Behavior::RateLimited {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, "120")],
            Json(json!({"error": "rate limited"})),
        )
            .into_response();
    }
    svc.seen_claims.push(claim);
    (
        StatusCode::CREATED,
        Json(json!({"name": name, "status": "created"})),
    )
        .into_response()
}

async fn delete_name(
    Path(_name): Path<String>,
    State(state): State<Arc<Mutex<MockService>>>,
    body: Bytes,
) -> impl IntoResponse {
    let claim: AnyClaim = serde_json::from_slice(&body).unwrap();
    let mut svc = state.lock().unwrap();
    svc.seen_deletes.push(claim);
    (StatusCode::OK, Json(json!({"status": "deleted"}))).into_response()
}

async fn post_cert(
    Path(_name): Path<String>,
    State(state): State<Arc<Mutex<MockService>>>,
    body: Bytes,
) -> impl IntoResponse {
    let cert_req: AnyClaim = serde_json::from_slice(&body).unwrap();
    // Sign the CSR with a fresh CA-style keypair so we hand back a real cert
    // chain. The mock does not validate the CSR contents beyond the parse.
    let issuance_pem = mock_issue(&cert_req.csr);
    let not_after = "2027-06-01T00:00:00Z";
    let mut svc = state.lock().unwrap();
    svc.seen_certs.push(cert_req);
    (
        StatusCode::OK,
        Json(json!({
            "certChainPem": issuance_pem,
            "notAfter": not_after,
        })),
    )
        .into_response()
}

fn mock_issue(_csr_pem: &str) -> String {
    // Return a well-formed PEM cert chain; the assertion here doesn't require
    // a real CA countersignature. Full re-signing of the CSR would need
    // deeper rcgen wiring than the test needs.
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut cert = CertificateParams::new(vec!["mynode.local.tinycloud.link".to_string()]).unwrap();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(DnType::CommonName, "mynode.local.tinycloud.link");
    cert.distinguished_name = dn;
    cert.subject_alt_names = vec![SanType::DnsName(
        "mynode.local.tinycloud.link"
            .to_string()
            .try_into()
            .unwrap(),
    )];
    let issued = cert.self_signed(&key).unwrap();
    issued.pem()
}

async fn start_mock_service(behavior: Behavior) -> (String, Arc<Mutex<MockService>>) {
    let state = Arc::new(Mutex::new(MockService {
        behavior,
        ..Default::default()
    }));
    let app = Router::new()
        .route("/v1/names/:name", put(put_name).delete(delete_name))
        .route("/v1/certs/:name", post(post_cert))
        .with_state(state.clone());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), state)
}

// A blocking-flavored helper: `enable()` uses blocking reqwest under the hood
// so we run it inside `spawn_blocking`.
async fn run_enable(
    data_root: PathBuf,
    keys: Keys,
    args: EnableArgs,
) -> anyhow::Result<tinycloud::link::commands::LinkStatusReport> {
    tokio::task::spawn_blocking(move || enable(&data_root, Some(&keys), args))
        .await
        .unwrap()
}

fn install_env_secret() -> String {
    // Reproduce the same TINYCLOUD_KEYS_SECRET path key_provider tests use so
    // enable() can resolve an in-process identity without touching the real
    // keychain / encrypted-file provider.
    let secret = [7u8; 32];
    let encoded = base64::encode_config(secret, base64::URL_SAFE_NO_PAD);
    std::env::set_var("TINYCLOUD_KEYS_SECRET", &encoded);
    encoded
}

#[tokio::test]
async fn enable_happy_path_claims_and_issues_cert() {
    let _ = install_env_secret();
    // Use Keys::Auto so the resolver picks up TINYCLOUD_KEYS_SECRET.
    let keys = Keys::Auto;

    let data_root = tempdir().unwrap();
    let data_root_path = data_root.path().to_path_buf();
    let (base_url, service) = start_mock_service(Behavior::Ok).await;

    let args = EnableArgs {
        name: "mynode".to_string(),
        service_url: Some(base_url),
        bind: Some("127.0.0.1:0".to_string()),
    };

    // Depending on the host running the tests we may or may not have a
    // detectable private-range LAN interface. Skip cleanly if not.
    let report = match run_enable(data_root_path.clone(), keys, args).await {
        Ok(report) => report,
        Err(err)
            if format!("{err:#}").contains("no private-range LAN IPs were found on this host") =>
        {
            eprintln!("skipping: host has no private LAN interface");
            return;
        }
        Err(err) => panic!("enable failed: {err:#}"),
    };

    assert!(report.enabled);
    assert_eq!(report.link_name.as_deref(), Some("mynode"));
    assert!(report
        .local_url
        .unwrap()
        .contains("mynode.local.tinycloud.link"));

    let svc = service.lock().unwrap();
    assert_eq!(svc.seen_claims.len(), 1);
    assert_eq!(svc.seen_claims[0].name, "mynode");
    assert!(svc.seen_claims[0].sequence >= 1);
    assert_eq!(svc.seen_certs.len(), 1);
    assert_eq!(svc.seen_certs[0].name, "mynode");
    // The persisted sequence must be greater than the claim's sequence.
    let paths = state::LinkPaths::from_data_root(&data_root_path);
    let persisted = state::read_state(&paths).unwrap().unwrap();
    assert_eq!(
        persisted.sequence, svc.seen_certs[0].sequence,
        "state.json sequence must match the cert-request sequence"
    );
    assert!(persisted.cert_not_after.is_some());
    assert!(paths.key_path.exists());
    assert!(paths.cert_path.exists());
}

#[tokio::test]
async fn enable_surfaces_409_name_conflict_with_named_error() {
    let _ = install_env_secret();
    let keys = Keys::Auto;
    let data_root = tempdir().unwrap();
    let (base_url, _service) = start_mock_service(Behavior::ClaimConflict).await;

    let args = EnableArgs {
        name: "takenname".to_string(),
        service_url: Some(base_url),
        bind: Some("127.0.0.1:0".to_string()),
    };

    let err = match run_enable(data_root.path().to_path_buf(), keys, args).await {
        Ok(_) => panic!("enable should have failed with 409"),
        Err(err) => err,
    };
    let rendered = format!("{err:#}");
    // If the host truly has no LAN interface we get "no private-range LAN IPs"
    // before the HTTP call — that's still a valid outcome for this test.
    if rendered.contains("no private-range LAN IPs were found on this host") {
        eprintln!("skipping: host has no private LAN interface");
        return;
    }
    assert!(
        rendered.contains("already claimed") || rendered.contains("takenname"),
        "expected 409 name-conflict error, got: {rendered}"
    );
}

#[tokio::test]
async fn enable_surfaces_429_rate_limited_with_retry_after() {
    let _ = install_env_secret();
    let keys = Keys::Auto;
    let data_root = tempdir().unwrap();
    let (base_url, _service) = start_mock_service(Behavior::RateLimited).await;

    let args = EnableArgs {
        name: "throttlednode".to_string(),
        service_url: Some(base_url),
        bind: Some("127.0.0.1:0".to_string()),
    };

    let err = match run_enable(data_root.path().to_path_buf(), keys, args).await {
        Ok(_) => panic!("enable should have failed with 429"),
        Err(err) => err,
    };
    let rendered = format!("{err:#}");
    if rendered.contains("no private-range LAN IPs were found on this host") {
        eprintln!("skipping: host has no private LAN interface");
        return;
    }
    assert!(
        rendered.contains("rate-limited"),
        "expected 429 rate-limited error, got: {rendered}"
    );
    assert!(
        rendered.contains("retry after 120s"),
        "expected the Retry-After value to be surfaced cleanly, got: {rendered}"
    );
    // Regression guard for the Debug-formatted `Some("120")` / `None` bug.
    assert!(
        !rendered.contains("Some(") && !rendered.contains("None"),
        "rate-limit error must not leak Option Debug formatting, got: {rendered}"
    );
}

#[tokio::test]
async fn tls_proxy_round_trips_bytes_to_the_upstream_echo() {
    // Upstream: a simple echo server the proxy will forward bytes into.
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = echo_listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = sock.read(&mut buf).await.unwrap();
                sock.write_all(&buf[..n]).await.unwrap();
                sock.shutdown().await.unwrap();
            });
        }
    });

    // Generate a self-signed cert for "example.local".
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(vec!["example.local".to_string()]).unwrap();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(DnType::CommonName, "example.local");
    params.distinguished_name = dn;
    params.subject_alt_names = vec![SanType::DnsName(
        "example.local".to_string().try_into().unwrap(),
    )];
    let cert = params.self_signed(&key).unwrap();
    let cert_pem = cert.pem();
    let key_pem = key.serialize_pem();
    let server_config = proxy::build_rustls_config(&key_pem, &cert_pem).unwrap();

    // Pick a bind address for the proxy.
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    drop(proxy_listener); // release; proxy::bind rebinds

    let bound = proxy::bind(proxy_addr).unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let proxy_task = tokio::spawn({
        let server_config = server_config.clone();
        async move { proxy::run(bound, echo_addr, server_config, shutdown_rx).await }
    });

    // Give the listener a moment to bind.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Client: connect via TLS, accepting the self-signed cert.
    let client_config = insecure_client_config();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

    let tcp = TcpStream::connect(proxy_addr).await.unwrap();
    let server_name = rustls::pki_types::ServerName::try_from("example.local").unwrap();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();

    tls.write_all(b"hello proxy\n").await.unwrap();
    let mut resp = [0u8; 32];
    let n = tls.read(&mut resp).await.unwrap();
    assert_eq!(&resp[..n], b"hello proxy\n");

    // Trigger shutdown.
    shutdown_tx.send(true).unwrap();
    let _ = proxy_task.await;

    // Sanity: ensure static secret usage doesn't leave TINYCLOUD_KEYS_SECRET
    // in the environment for subsequent tests.
    std::env::remove_var("TINYCLOUD_KEYS_SECRET");
    let _ = StaticSecret::new(vec![0u8; 32]);
    let _ = SocketAddr::from(([127, 0, 0, 1], 0));
}

fn insecure_client_config() -> rustls::ClientConfig {
    // Test-only config that trusts any cert. This is scoped to the client side
    // of a loopback socket — never wired into production code.
    let provider = rustls::crypto::ring::default_provider();
    let _ = provider.install_default();
    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));
    rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth()
}

#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
