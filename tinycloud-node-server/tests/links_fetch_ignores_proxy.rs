//! The links fetch never goes through a proxy. This test owns its process: it
//! sets `HTTPS_PROXY` and `ALL_PROXY` before any HTTP client exists (reqwest
//! reads the system proxy once per process), runs the production fetcher with
//! no test seams, and shows the connection goes to the configured origin and
//! not to the proxy.

use std::{sync::Arc, time::Duration};
use tinycloud::{
    config::Config,
    egress::EgressPolicy,
    links_fetch::{ApiLinkFetcher, LinkFetchError, LinkId, LinkRecordFetcher, LinksOrigin},
};
use tokio::net::TcpListener;

async fn count_connections(listener: TcpListener) -> usize {
    let mut seen = 0;
    while let Ok(Ok((stream, _))) =
        tokio::time::timeout(Duration::from_millis(300), listener.accept()).await
    {
        seen += 1;
        drop(stream);
    }
    seen
}

#[tokio::test]
async fn the_fetch_ignores_the_proxy_environment() {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_url = format!("http://{}", proxy.local_addr().unwrap());
    std::env::set_var("HTTPS_PROXY", &proxy_url);
    std::env::set_var("https_proxy", &proxy_url);
    std::env::set_var("ALL_PROXY", &proxy_url);
    std::env::set_var("all_proxy", &proxy_url);
    std::env::remove_var("NO_PROXY");
    std::env::remove_var("no_proxy");

    // A loopback origin, permitted by the private-network flag; the listener
    // is not a TLS server, so the fetch fails, but where it connects shows.
    let links_origin =
        LinksOrigin::parse(&format!("https://{}", origin.local_addr().unwrap())).unwrap();
    let policy = Arc::new(EgressPolicy::from_config(&Config::default(), None).unwrap());
    let fetcher = ApiLinkFetcher::new(policy, links_origin, true);
    let id = LinkId::parse("lqdw5iopqq2tkkvjj6gbbi5vbv").unwrap();
    assert_eq!(
        fetcher.fetch(&id).await.err(),
        Some(LinkFetchError::Unavailable)
    );

    let (to_origin, to_proxy) = tokio::join!(count_connections(origin), count_connections(proxy));
    assert!(
        to_origin >= 1,
        "the fetch connected to the configured origin"
    );
    assert_eq!(to_proxy, 0, "the fetch never connected to the proxy");
}
