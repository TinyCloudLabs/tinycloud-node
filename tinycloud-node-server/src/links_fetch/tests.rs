use super::*;
use crate::egress::test_support::TestLookup;
use hyper::{service::service_fn, Body, Request, Response};
use parking_lot::Mutex;
use std::{convert::Infallible, sync::Arc};

const ID: &str = "lqdw5iopqq2tkkvjj6gbbi5vbv";
const HOST: &str = "links.test";

type Seen = Arc<Mutex<Vec<(String, hyper::HeaderMap)>>>;

/// A TLS test server for the links API. TLS stays on: the test seam is the
/// policy's test root and loopback allowance, which exist only under
/// `cfg(test)`; the production path is `https` plus the pinned address.
struct LinksServer {
    port: u16,
    certificate: reqwest::Certificate,
    seen: Seen,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for LinksServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl LinksServer {
    fn requests(&self) -> usize {
        self.seen.lock().len()
    }
}

async fn serve(
    respond: impl Fn(&Request<Body>) -> Response<Body> + Send + Sync + 'static,
) -> LinksServer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let generated = rcgen::generate_simple_self_signed(vec![HOST.to_owned()]).unwrap();
    let certificate = reqwest::Certificate::from_pem(generated.cert.pem().as_bytes()).unwrap();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(generated.key_pair.serialize_der());
    let tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![generated.cert.der().clone()], key.into())
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let seen: Seen = Arc::default();
    let respond = Arc::new(respond);
    let recorded = seen.clone();
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let recorded = recorded.clone();
            let respond = respond.clone();
            tokio::spawn(async move {
                let Ok(stream) = acceptor.accept(stream).await else {
                    return;
                };
                let service = service_fn(move |request: Request<Body>| {
                    let recorded = recorded.clone();
                    let respond = respond.clone();
                    async move {
                        recorded
                            .lock()
                            .push((request.uri().to_string(), request.headers().clone()));
                        Ok::<_, Infallible>(respond(&request))
                    }
                });
                let _ = hyper::server::conn::Http::new()
                    .serve_connection(stream, service)
                    .await;
            });
        }
    });
    LinksServer {
        port,
        certificate,
        seen,
        task,
    }
}

fn ok(record: Option<&str>, body: Vec<u8>) -> Response<Body> {
    let mut response = Response::builder()
        .status(200)
        .header("content-type", "application/octet-stream");
    if let Some(record) = record {
        response = response.header("x-link-record", record);
    }
    response.body(Body::from(body)).unwrap()
}

fn status(code: u16) -> Response<Body> {
    Response::builder()
        .status(code)
        .body(Body::empty())
        .unwrap()
}

struct Rig {
    fetcher: ApiLinkFetcher,
    lookup: Arc<TestLookup>,
    server: LinksServer,
}

async fn rig(respond: impl Fn(&Request<Body>) -> Response<Body> + Send + Sync + 'static) -> Rig {
    let server = serve(respond).await;
    let lookup = Arc::new(TestLookup::default());
    lookup.set(HOST, &["127.0.0.1"]).await;
    let policy = Arc::new(
        EgressPolicy::for_test(Vec::new(), lookup.clone(), true)
            .with_test_root(server.certificate.clone()),
    );
    let origin = LinksOrigin::parse(&format!("https://{HOST}:{}", server.port)).unwrap();
    Rig {
        fetcher: ApiLinkFetcher::new(policy, origin, false),
        lookup,
        server,
    }
}

fn id() -> LinkId {
    LinkId::parse(ID).unwrap()
}

#[tokio::test]
async fn one_get_to_the_configured_origin_with_the_validated_id() {
    let rig = rig(|_| ok(Some("record-header"), b"sealed body".to_vec())).await;
    let fetched = rig.fetcher.fetch(&id()).await.unwrap();
    assert_eq!(fetched.record_header, "record-header");
    assert_eq!(fetched.body, b"sealed body");
    assert_eq!(rig.server.requests(), 1);
    assert_eq!(rig.lookup.call_count(), 1);
    let seen = rig.server.seen.lock();
    let (uri, headers) = &seen[0];
    assert_eq!(uri, &format!("/v1/links/{ID}"));
    assert_eq!(
        headers.get("host").unwrap(),
        format!("{HOST}:{}", rig.server.port).as_str()
    );
    assert_eq!(headers.get("accept-encoding").unwrap(), "identity");
    for absent in ["authorization", "cookie", "referer", "proxy-authorization"] {
        assert!(headers.get(absent).is_none(), "{absent}");
    }
}

#[tokio::test]
async fn the_api_404_is_not_found_and_every_other_status_fails_closed() {
    for (code, expected) in [
        (404, LinkFetchError::NotFound),
        (429, LinkFetchError::Unavailable),
        (500, LinkFetchError::Unavailable),
        (502, LinkFetchError::Unavailable),
        (503, LinkFetchError::Unavailable),
        (400, LinkFetchError::Unavailable),
        (401, LinkFetchError::Unavailable),
        (403, LinkFetchError::Unavailable),
        (204, LinkFetchError::Unavailable),
    ] {
        let rig = rig(move |_| status(code)).await;
        assert_eq!(
            rig.fetcher.fetch(&id()).await.err(),
            Some(expected),
            "{code}"
        );
        // One attempt: no retry on any status.
        assert_eq!(rig.server.requests(), 1, "{code}");
    }
}

#[tokio::test]
async fn a_redirect_is_not_followed() {
    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let location = format!("http://{}/elsewhere", target.local_addr().unwrap());
    let rig = rig(move |_| {
        Response::builder()
            .status(302)
            .header("location", location.clone())
            .body(Body::empty())
            .unwrap()
    })
    .await;
    assert_eq!(
        rig.fetcher.fetch(&id()).await.err(),
        Some(LinkFetchError::Unavailable)
    );
    assert_eq!(rig.server.requests(), 1);
    assert!(
        tokio::time::timeout(Duration::from_millis(150), target.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn the_body_cap_holds_while_streaming() {
    // Exactly at the cap is accepted.
    let rig_ok = rig(|_| ok(Some("r"), vec![7; MAX_LINK_BODY_BYTES])).await;
    assert_eq!(
        rig_ok.fetcher.fetch(&id()).await.unwrap().body.len(),
        MAX_LINK_BODY_BYTES
    );

    // One byte over, sent with a Content-Length.
    let rig_over = rig(|_| ok(Some("r"), vec![7; MAX_LINK_BODY_BYTES + 1])).await;
    assert_eq!(
        rig_over.fetcher.fetch(&id()).await.err(),
        Some(LinkFetchError::Unavailable)
    );

    // Over the cap with no Content-Length: the read stops at the cap. The
    // server would need two seconds to finish its stream, so a fetch that
    // returns at once did not read to the end.
    let rig_stream = rig(move |_| {
        let (mut sender, body) = Body::channel();
        tokio::spawn(async move {
            for _ in 0..100 {
                if sender
                    .send_data(hyper::body::Bytes::from(vec![9; 16_384]))
                    .await
                    .is_err()
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });
        Response::builder()
            .status(200)
            .header("x-link-record", "r")
            .body(body)
            .unwrap()
    })
    .await;
    let started = std::time::Instant::now();
    assert_eq!(
        rig_stream.fetcher.fetch(&id()).await.err(),
        Some(LinkFetchError::Unavailable)
    );
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[tokio::test]
async fn a_slow_body_runs_into_the_total_deadline() {
    let rig = rig(|_| {
        let (mut sender, body) = Body::channel();
        tokio::spawn(async move {
            let _ = sender
                .send_data(hyper::body::Bytes::from_static(b"x"))
                .await;
            tokio::time::sleep(Duration::from_secs(30)).await;
            let _ = sender
                .send_data(hyper::body::Bytes::from_static(b"y"))
                .await;
        });
        Response::builder()
            .status(200)
            .header("x-link-record", "r")
            .body(body)
            .unwrap()
    })
    .await;
    let fetcher = rig.fetcher.with_total_timeout(Duration::from_millis(400));
    let started = std::time::Instant::now();
    assert_eq!(
        fetcher.fetch(&id()).await.err(),
        Some(LinkFetchError::Unavailable)
    );
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn the_record_header_is_required_once_and_capped() {
    let missing = rig(|_| ok(None, b"body".to_vec())).await;
    assert_eq!(
        missing.fetcher.fetch(&id()).await.err(),
        Some(LinkFetchError::RecordHeaderInvalid)
    );

    let twice = rig(|_| {
        Response::builder()
            .status(200)
            .header("x-link-record", "a")
            .header("x-link-record", "b")
            .body(Body::from("body"))
            .unwrap()
    })
    .await;
    assert_eq!(
        twice.fetcher.fetch(&id()).await.err(),
        Some(LinkFetchError::RecordHeaderInvalid)
    );

    let at_cap = "a".repeat(MAX_LINK_RECORD_HEADER_BYTES);
    let value = at_cap.clone();
    let rig_cap = rig(move |_| ok(Some(&value), b"body".to_vec())).await;
    assert_eq!(
        rig_cap.fetcher.fetch(&id()).await.unwrap().record_header,
        at_cap
    );

    let over = "a".repeat(MAX_LINK_RECORD_HEADER_BYTES + 1);
    let rig_over = rig(move |_| ok(Some(&over), b"body".to_vec())).await;
    assert_eq!(
        rig_over.fetcher.fetch(&id()).await.err(),
        Some(LinkFetchError::Unavailable)
    );
}

#[tokio::test]
async fn the_connection_goes_to_the_address_that_was_vetted() {
    // The first answer is vetted and used; a second answer that would be
    // refused is never asked for, because the name is resolved once.
    let server = serve(|_| ok(Some("r"), b"body".to_vec())).await;
    let lookup = Arc::new(TestLookup::default());
    lookup
        .sequence(HOST, &[&["127.0.0.1"], &["10.0.0.1"]])
        .await;
    let policy = Arc::new(
        EgressPolicy::for_test(Vec::new(), lookup.clone(), true)
            .with_test_root(server.certificate.clone()),
    );
    let origin = LinksOrigin::parse(&format!("https://{HOST}:{}", server.port)).unwrap();
    let fetcher = ApiLinkFetcher::new(policy, origin, false);
    assert!(fetcher.fetch(&id()).await.is_ok());
    assert_eq!(lookup.call_count(), 1);
    assert_eq!(server.requests(), 1);
}

#[tokio::test]
async fn a_private_first_answer_is_refused_without_a_connection() {
    let server = serve(|_| ok(Some("r"), b"body".to_vec())).await;
    let lookup = Arc::new(TestLookup::default());
    lookup
        .sequence(HOST, &[&["10.0.0.1"], &["127.0.0.1"]])
        .await;
    let policy = Arc::new(
        EgressPolicy::for_test(Vec::new(), lookup.clone(), true)
            .with_test_root(server.certificate.clone()),
    );
    let origin = LinksOrigin::parse(&format!("https://{HOST}:{}", server.port)).unwrap();
    let fetcher = ApiLinkFetcher::new(policy, origin, false);
    assert_eq!(
        fetcher.fetch(&id()).await.err(),
        Some(LinkFetchError::Unavailable)
    );
    assert_eq!(lookup.call_count(), 1);
    assert_eq!(server.requests(), 0);
}

#[tokio::test]
async fn the_private_scope_admits_private_classes_and_nothing_else() {
    let lookup = Arc::new(TestLookup::default());
    for (host, address) in [
        ("private.test", "10.1.2.3"),
        ("cgnat.test", "100.64.0.9"),
        ("linklocal.test", "169.254.1.1"),
        ("multicast.test", "224.0.0.1"),
        ("reserved.test", "240.0.0.1"),
        ("unspecified.test", "0.0.0.0"),
    ] {
        lookup.set(host, &[address]).await;
    }
    let policy = EgressPolicy::for_test(Vec::new(), lookup, false);
    for (host, allowed_private) in [
        ("private.test", true),
        ("cgnat.test", true),
        ("linklocal.test", true),
        ("multicast.test", false),
        ("reserved.test", false),
        ("unspecified.test", false),
    ] {
        let url = Url::parse(&format!("https://{host}/")).unwrap();
        assert!(
            policy
                .resolve_url_scoped(&url, AddressScope::PublicOnly)
                .await
                .is_err(),
            "{host} under the public scope"
        );
        assert_eq!(
            policy
                .resolve_url_scoped(&url, AddressScope::AllowPrivate)
                .await
                .is_ok(),
            allowed_private,
            "{host} under the private scope"
        );
    }
}

#[test]
fn only_a_26_character_base32_id_reaches_the_path() {
    assert!(LinkId::parse(ID).is_some());
    assert!(LinkId::parse("22222222222222222222222222").is_some());
    for bad in [
        "",
        "lqdw5iopqq2tkkvjj6gbbi5vb",
        "lqdw5iopqq2tkkvjj6gbbi5vbvv",
        "LQDW5IOPQQ2TKKVJJ6GBBI5VBV",
        "1qdw5iopqq2tkkvjj6gbbi5vbv",
        "lqdw5iopqq2tkkvjj6gbbi5vb8",
        "lqdw5iopqq2tkkvjj6gbbi5v/v",
        "../../..lqdw5iopqq2tkkvjj6g",
        "lqdw5iopqq2tkkvjj6gbbi5vb?",
        "lqdw5iopqq2tkkvjj6gbbi5vb\n",
        "lqdw5iopqq2tkkvjj6gbbi5vb\u{e9}",
    ] {
        assert!(LinkId::parse(bad).is_none(), "{bad:?}");
    }
}

#[test]
fn the_configured_origin_is_exactly_https_host_and_port() {
    for good in [
        "https://api.tinycloud.xyz",
        "https://api.tinycloud.xyz:8443",
        "https://links.example.org",
        "https://1.2.3.4",
        "https://[2606:4700::1111]:8443",
    ] {
        assert!(LinksOrigin::parse(good).is_ok(), "{good}");
    }
    for bad in [
        "",
        "api.tinycloud.xyz",
        "http://api.tinycloud.xyz",
        "https://api.tinycloud.xyz/",
        "https://api.tinycloud.xyz/v1",
        "https://api.tinycloud.xyz?x=1",
        "https://api.tinycloud.xyz#x",
        "https://user@api.tinycloud.xyz",
        "https://user:pass@api.tinycloud.xyz",
        "https://:@api.tinycloud.xyz",
        "https://API.tinycloud.xyz",
        "https://api.tinycloud.xyz:443",
        "https://api.tinycloud.xyz:0",
        "https://api.tinycloud.xyz:99999",
        "https://api.tinycloud.xyz:",
        "https://",
        "https:///",
        "https://api.tinycloud.xyz ",
        " https://api.tinycloud.xyz",
        "https://api.tinycloud.xyz\\@evil.example",
        "ftp://api.tinycloud.xyz",
        "wss://api.tinycloud.xyz",
        "https://0x7f.1",
        "https://2130706433",
    ] {
        assert!(LinksOrigin::parse(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn private_hosts_are_refused_unless_the_self_host_flag_is_set() {
    for host in [
        "https://127.0.0.1",
        "https://10.0.0.5",
        "https://172.16.0.1:8443",
        "https://192.168.1.1",
        "https://169.254.169.254",
        "https://100.64.0.1",
        "https://0.0.0.0",
        "https://224.0.0.1",
        "https://[::1]",
        "https://[fe80::1]",
        "https://[fc00::1]",
        "https://[::ffff:10.0.0.1]",
        "https://localhost",
        "https://api.localhost",
    ] {
        assert!(LinksOrigin::validate(host, false, None).is_err(), "{host}");
    }
    for host in [
        "https://127.0.0.1",
        "https://10.0.0.5",
        "https://192.168.1.1",
        "https://169.254.169.254",
        "https://100.64.0.1",
        "https://[::1]",
        "https://[fc00::1]",
        "https://localhost",
    ] {
        assert!(LinksOrigin::validate(host, true, None).is_ok(), "{host}");
    }
    // The flag does not make a multicast or unspecified address usable.
    for host in ["https://0.0.0.0", "https://224.0.0.1", "https://[ff02::1]"] {
        assert!(LinksOrigin::validate(host, true, None).is_err(), "{host}");
    }
    assert!(LinksOrigin::validate("https://api.tinycloud.xyz", false, None).is_ok());
}

#[test]
fn a_host_that_resolves_to_a_private_address_is_refused() {
    let answers = |answers: &'static [&'static str]| {
        move |_: &str, port: u16| {
            assert_eq!(port, 443);
            Some(answers.iter().map(|ip| ip.parse().unwrap()).collect())
        }
    };
    let check = |allow: bool, resolve: &dyn Fn(&str, u16) -> Option<Vec<IpAddr>>| {
        LinksOrigin::validate("https://links.example.org", allow, Some(resolve)).is_ok()
    };
    assert!(check(false, &answers(&["93.184.216.34"])));
    assert!(check(
        false,
        &answers(&["93.184.216.34", "2606:2800:220:1::1"])
    ));
    assert!(!check(false, &answers(&["10.0.0.7"])));
    assert!(!check(false, &answers(&["93.184.216.34", "10.0.0.7"])));
    assert!(!check(false, &answers(&["127.0.0.1"])));
    assert!(!check(false, &answers(&["::1"])));
    assert!(!check(false, &answers(&["100.100.100.100"])));
    assert!(!check(false, &answers(&["::ffff:192.168.0.1"])));
    assert!(check(true, &answers(&["10.0.0.7"])));
    assert!(!check(true, &answers(&["224.0.0.1"])));
    // A failed lookup is not a refusal at load; every fetch vets its address.
    assert!(check(false, &|_, _| None));
}
