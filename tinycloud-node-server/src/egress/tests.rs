use super::test_support::TestLookup;
use super::*;

#[test]
fn tc1132_special_use_classes_and_public_boundaries() {
    for (class, addresses) in [
        ("this_network", vec!["0.0.0.0", "0.255.255.255"]),
        (
            "private",
            vec!["10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1"],
        ),
        ("cgnat", vec!["100.64.0.1", "100.127.255.255"]),
        (
            "loopback",
            vec![
                "127.0.0.1",
                "::1",
                "::ffff:127.0.0.1",
                "::127.0.0.1",
                "2002:7f00:1::",
            ],
        ),
        (
            "link_local",
            vec![
                "169.254.169.254",
                "169.254.170.2",
                "fe80::1",
                "febf::1",
                "64:ff9b::a9fe:a9fe",
            ],
        ),
        ("ietf", vec!["192.0.0.1"]),
        (
            "documentation",
            vec!["192.0.2.1", "198.51.100.1", "203.0.113.1", "2001:db8::1"],
        ),
        ("benchmark", vec!["198.18.0.1", "198.19.255.255"]),
        ("6to4_relay", vec!["192.88.99.1"]),
        ("multicast", vec!["224.0.0.1", "239.255.255.255", "ff02::1"]),
        ("reserved", vec!["240.0.0.1", "255.255.255.255"]),
        ("unspecified", vec!["::"]),
        ("site_local", vec!["fec0::1", "feff::1"]),
        ("unique_local", vec!["fc00::1", "fd00:ec2::254"]),
        ("discard", vec!["100::1"]),
        ("teredo", vec!["2001::1"]),
    ] {
        for address in addresses {
            assert_eq!(
                EgressPolicy::forbidden(address.parse().unwrap()),
                Some(class),
                "{address}"
            );
        }
    }
    for address in [
        "1.1.1.1",
        "192.2.1.1",
        "198.51.0.1",
        "192.0.3.1",
        "198.51.99.255",
        "198.51.101.0",
        "100.63.255.255",
        "100.128.0.0",
        "172.15.255.255",
        "172.32.0.0",
        "198.17.255.255",
        "198.20.0.0",
        "2606:4700::1111",
        "::ffff:8.8.8.8",
        "::8.8.8.8",
        "64:ff9b::808:808",
        "64:ff9b:1::808:808",
        "2002:808:808::",
    ] {
        assert_eq!(
            EgressPolicy::forbidden(address.parse().unwrap()),
            None,
            "{address}"
        );
    }
    for address in [
        "64:ff9b:1::a00:1",
        "64:ff9b:1:a00:0:100::",
        "64:ff9b:1:10a:0:100::",
        "64:ff9b:1:1:a:1::",
    ] {
        assert!(
            EgressPolicy::forbidden(address.parse().unwrap()).is_some(),
            "{address}"
        );
    }
}

#[tokio::test]
async fn tc1132_mixed_dns_exposes_only_vetted_addresses_to_reqwest() {
    let lookup = Arc::new(TestLookup::default());
    lookup
        .set(
            "mixed.test",
            &["10.0.0.1", "169.254.169.254", "1.1.1.1", "2606:4700::1111"],
        )
        .await;
    let policy = Arc::new(EgressPolicy::for_test(vec![], lookup.clone(), false));
    let destination = policy
        .resolve_url(&Url::parse("https://mixed.test/").unwrap())
        .await
        .unwrap();
    let resolver = PolicyResolver {
        policy,
        destination,
    };
    let addresses: Vec<_> = resolver
        .resolve("mixed.test".parse().unwrap())
        .await
        .unwrap()
        .collect();
    assert_eq!(
        addresses,
        vec![
            "1.1.1.1:443".parse::<SocketAddr>().unwrap(),
            "[2606:4700::1111]:443".parse().unwrap()
        ]
    );
    assert_eq!(lookup.call_count(), 1, "no second DNS lookup at connect");
}

#[tokio::test]
async fn tc1132_database_and_other_endpoint_aliases_are_denied_on_every_port() {
    let lookup = Arc::new(TestLookup::default());
    lookup.set("db.test", &["1.1.1.1"]).await;
    lookup.set("quota.test", &["8.8.8.8"]).await;
    lookup.set("callback.test", &["1.1.1.1", "8.8.8.8"]).await;
    let mut config = Config::default();
    config.storage.database = Some("postgres://user:password@db.test:5432/node".into());
    let mut policy =
        EgressPolicy::from_config(&config, Some("https://quota.test/internal")).unwrap();
    policy.lookup = lookup;
    policy.refresh().await.unwrap();
    for url in [
        "https://callback.test/",
        "https://1.1.1.1:8443/",
        "https://[64:ff9b::101:101]/",
        "https://8.8.8.8/",
    ] {
        assert!(
            matches!(
                policy.resolve_url(&Url::parse(url).unwrap()).await,
                Err(EgressError::Forbidden)
            ),
            "{url}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn tc1132_endpoint_refresh_is_periodic_fail_closed_and_recovers() {
    let lookup = Arc::new(TestLookup::default());
    lookup.set("db.test", &["1.1.1.1"]).await;
    let policy = EgressPolicy::for_test(vec!["db.test".into()], lookup.clone(), false);
    policy.refresh().await.unwrap();
    let old = Url::parse("https://1.1.1.1/").unwrap();
    let new = Url::parse("https://8.8.8.8/").unwrap();
    assert!(policy.resolve_url(&new).await.is_ok());
    lookup.set("db.test", &[]).await;
    tokio::time::advance(REFRESH_INTERVAL).await;
    assert!(matches!(
        policy.resolve_url(&new).await,
        Err(EgressError::Unavailable)
    ));
    assert!(matches!(
        policy.resolve_url(&old).await,
        Err(EgressError::Unavailable)
    ));
    lookup.set("db.test", &["8.8.8.8"]).await;
    tokio::time::advance(REFRESH_INTERVAL).await;
    assert!(matches!(
        policy.resolve_url(&new).await,
        Err(EgressError::Forbidden)
    ));
    assert!(policy.resolve_url(&old).await.is_ok());
}

struct StalledLookup;
#[async_trait::async_trait]
impl LookupHost for StalledLookup {
    async fn lookup(&self, _: &str) -> Result<Vec<IpAddr>, EgressError> {
        std::future::pending().await
    }
}

#[tokio::test(start_paused = true)]
async fn tc1132_registration_dns_and_internal_refresh_have_one_second_deadlines() {
    let policy = EgressPolicy::for_test(vec![], Arc::new(StalledLookup), false);
    let start = Instant::now();
    let result =
        crate::routes::hooks::validate_webhook_callback_url("https://slow.test/", &policy).await;
    assert_eq!(result.err().unwrap().0, rocket::http::Status::BadRequest);
    assert_eq!(start.elapsed(), DNS_TIMEOUT);
    let policy = EgressPolicy::for_test(vec!["slow.test".into()], Arc::new(StalledLookup), false);
    let start = Instant::now();
    assert!(matches!(
        policy.refresh().await,
        Err(EgressError::Unavailable)
    ));
    assert_eq!(start.elapsed(), DNS_TIMEOUT);
    assert!(matches!(
        policy
            .resolve_url(&Url::parse("https://1.1.1.1/").unwrap())
            .await,
        Err(EgressError::Unavailable)
    ));
}

#[tokio::test]
async fn tc1132_redirects_never_reach_another_listener() -> anyhow::Result<()> {
    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let mut callback = test_support::callback_server(
        302,
        Some(format!("http://{}/redirected", target.local_addr()?)),
    )
    .await?;
    let lookup = Arc::new(TestLookup::default());
    lookup.set("callback.test", &["127.0.0.1"]).await;
    let policy = Arc::new(
        EgressPolicy::for_test(vec![], lookup, true).with_test_root(callback.certificate.clone()),
    );
    let url = Url::parse(&callback.url)?;
    let destination = policy.resolve_url(&url).await?;
    let response = client(policy, destination, Duration::from_secs(3))?
        .post(url)
        .body("signed event")
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::FOUND);
    assert_eq!(callback.requests.recv().await.unwrap().0, b"signed event");
    assert!(
        tokio::time::timeout(Duration::from_millis(100), target.accept())
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn tc1132_connect_time_policy_refuses_a_previously_vetted_now_internal_address(
) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let lookup = Arc::new(TestLookup::default());
    lookup.set("callback.test", &["127.0.0.1"]).await;
    lookup.set("db.test", &["1.1.1.1"]).await;
    let policy = Arc::new(EgressPolicy::for_test(
        vec!["db.test".into()],
        lookup.clone(),
        true,
    ));
    policy.refresh().await?;
    let url = Url::parse(&format!(
        "https://callback.test:{}/",
        listener.local_addr()?.port()
    ))?;
    let destination = policy.resolve_url(&url).await?;
    lookup.set("db.test", &["127.0.0.1"]).await;
    policy.refresh().await?;
    let error = client(policy, destination, Duration::from_secs(2))?
        .post(url)
        .send()
        .await
        .unwrap_err();
    assert!(error.to_string().contains("no permitted address"));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn tc1132_tls_connect_stall_is_bounded_before_total_timeout() -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let stall = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(5)).await;
    });
    let lookup = Arc::new(TestLookup::default());
    lookup.set("callback.test", &["127.0.0.1"]).await;
    let policy = Arc::new(EgressPolicy::for_test(vec![], lookup, true));
    let url = Url::parse(&format!("https://callback.test:{}/", address.port()))?;
    let destination = policy.resolve_url(&url).await?;
    let start = Instant::now();
    let error = client(policy, destination, Duration::from_secs(10))?
        .post(url)
        .send()
        .await
        .unwrap_err();
    assert!(error.is_timeout(), "{error}");
    assert!(start.elapsed() >= Duration::from_millis(1800));
    assert!(start.elapsed() < Duration::from_secs(3));
    stall.abort();
    Ok(())
}
