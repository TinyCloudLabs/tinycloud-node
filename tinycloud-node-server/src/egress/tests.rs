use super::test_support::TestLookup;
use super::*;

#[test]
fn tc1132_special_use_classes_and_public_boundaries() {
    for (class, addresses) in [
        ("this_network", vec!["0.0.0.0", "0.255.255.255"]),
        (
            "private",
            vec![
                "10.0.0.1",
                "172.16.0.1",
                "172.31.255.255",
                "192.168.1.1",
                "64:ff9b:1:808:8:808:a00:0",
            ],
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
                "64:ff9b:1:808:8:808:7f00:0",
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
        "64:ff9b:1:808:8:808:800:0",
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
    let denied = policy.deny.read().await.addresses.clone();
    let resolver = PolicyResolver {
        host: destination.url().host_str().unwrap().to_owned(),
        denied,
        addresses: destination.addresses,
        scope: destination.scope,
        deny_set_exempt: destination.deny_set_exempt,
        policy,
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

#[tokio::test]
async fn tc1737_links_origin_exempts_only_internal_address_overlap() -> anyhow::Result<()> {
    let lookup = Arc::new(TestLookup::default());
    lookup.set("quota.test", &["1.1.1.1"]).await;
    lookup.set("links.test", &["1.1.1.1"]).await;
    lookup.set("other.test", &["8.8.8.8"]).await;
    let policy = EgressPolicy::for_test(vec!["quota.test".into()], lookup, false);
    policy.refresh().await?;
    let origin = crate::links_fetch::LinksOrigin::parse("https://links.test").unwrap();
    let links = Url::parse("https://links.test/v1/links/record")?;
    assert!(matches!(
        policy
            .resolve_url_scoped(&links, AddressScope::PublicOnly)
            .await,
        Err(EgressError::Forbidden)
    ));
    let destination = policy
        .resolve_links_origin(&origin, &links, AddressScope::PublicOnly)
        .await?;
    assert!(destination.deny_set_exempt);
    assert_eq!(destination.addresses.as_ref(), &["1.1.1.1:443".parse()?]);
    let other = Url::parse("https://other.test/")?;
    assert!(!policy.resolve_url(&other).await?.deny_set_exempt);
    assert!(
        !policy
            .resolve_url_scoped(&other, AddressScope::AllowPrivate)
            .await?
            .deny_set_exempt
    );
    assert!(matches!(
        policy
            .resolve_links_origin(&origin, &other, AddressScope::PublicOnly)
            .await,
        Err(EgressError::Forbidden)
    ));
    Ok(())
}

#[tokio::test]
async fn tc1737_links_exemption_still_refuses_special_use_addresses() -> anyhow::Result<()> {
    let lookup = Arc::new(TestLookup::default());
    for (host, ip) in [
        ("private.test", "10.0.0.1"),
        ("loopback.test", "127.0.0.1"),
        ("cgnat.test", "100.64.0.1"),
        ("metadata.test", "169.254.169.254"),
    ] {
        lookup.set(host, &[ip]).await;
    }
    let policy = EgressPolicy::for_test(Vec::new(), lookup, false);
    for host in [
        "private.test",
        "loopback.test",
        "cgnat.test",
        "metadata.test",
    ] {
        let origin = crate::links_fetch::LinksOrigin::parse(&format!("https://{host}")).unwrap();
        let url = Url::parse(&format!("https://{host}/v1/links/record"))?;
        assert!(
            matches!(
                policy
                    .resolve_links_origin(&origin, &url, AddressScope::PublicOnly)
                    .await,
                Err(EgressError::Forbidden)
            ),
            "{host}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn tc1737_exempt_destination_remains_vetted_at_connect_time() -> anyhow::Result<()> {
    let mut server = test_support::callback_server_for_host("links.test", 200, None).await?;
    let lookup = Arc::new(TestLookup::default());
    lookup.set("quota.test", &["127.0.0.1"]).await;
    lookup.set("links.test", &["127.0.0.1"]).await;
    let policy = Arc::new(
        EgressPolicy::for_test(vec!["quota.test".into()], lookup.clone(), true)
            .with_test_root(server.certificate.clone()),
    );
    policy.refresh().await?;
    let origin = crate::links_fetch::LinksOrigin::parse(
        &Url::parse(&server.url)?.origin().ascii_serialization(),
    )
    .unwrap();
    let url = Url::parse(&server.url)?;
    let destination = policy
        .resolve_links_origin(&origin, &url, AddressScope::PublicOnly)
        .await?;
    let denied = policy.deny.read().await.addresses.clone();
    let (client, pinned_url) =
        pinned_client(&policy, destination, &denied, Duration::from_secs(3))?;
    assert_eq!(
        client.get(pinned_url).send().await?.status(),
        reqwest::StatusCode::OK
    );
    assert_eq!(server.requests.recv().await.unwrap().0, b"");
    assert_eq!(lookup.call_count(), 2, "no second links lookup at connect");
    Ok(())
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
    assert_eq!(
        result.err().unwrap().into_http_error().0,
        rocket::http::Status::BadRequest
    );
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
    let response = post(policy, destination, Duration::from_secs(3))
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
    let error = post(policy, destination, Duration::from_secs(2))
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
    let error = post(policy, destination, Duration::from_secs(10))
        .send()
        .await
        .unwrap_err();
    assert!(
        matches!(&error, SendError::Transport(error) if error.is_timeout()),
        "{error}"
    );
    assert!(start.elapsed() >= Duration::from_millis(1800));
    assert!(start.elapsed() < Duration::from_secs(3));
    stall.abort();
    Ok(())
}

#[tokio::test]
async fn tc1132_literal_vetted_before_refresh_never_connects_after_becoming_internal(
) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let lookup = Arc::new(TestLookup::default());
    lookup.set("db.test", &["192.2.1.1"]).await;
    let policy = Arc::new(EgressPolicy::for_test(
        vec!["db.test".into()],
        lookup.clone(),
        true,
    ));
    policy.refresh().await?;
    let url = Url::parse(&format!(
        "https://127.0.0.1:{}/hooks",
        listener.local_addr()?.port()
    ))?;
    let destination = policy.resolve_url(&url).await?;
    let request = post(policy.clone(), destination, Duration::from_secs(2));
    lookup.set("db.test", &["127.0.0.1"]).await;
    policy.refresh().await?;
    assert!(matches!(
        policy.resolve_url(&url).await,
        Err(EgressError::Forbidden)
    ));
    let error = request.send().await.unwrap_err();
    assert!(
        error.to_string().contains("no permitted address"),
        "{error}"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn tc1132_send_rechecks_mixed_snapshot_without_contacting_newly_denied_address(
) -> anyhow::Result<()> {
    let mut callback = test_support::callback_server(200, None).await?;
    let url = Url::parse(&callback.url)?;
    let denied =
        tokio::net::TcpListener::bind(format!("127.0.0.2:{}", url.port().unwrap())).await?;
    let lookup = Arc::new(TestLookup::default());
    lookup.set("db.test", &["192.2.1.1"]).await;
    lookup
        .set("callback.test", &["127.0.0.2", "127.0.0.1"])
        .await;
    let policy = Arc::new(
        EgressPolicy::for_test(vec!["db.test".into()], lookup.clone(), true)
            .with_test_root(callback.certificate.clone()),
    );
    policy.refresh().await?;
    let destination = policy.resolve_url(&url).await?;
    let request = post(policy.clone(), destination, Duration::from_secs(3)).body("same body");
    lookup.set("db.test", &["127.0.0.2"]).await;
    policy.refresh().await?;
    assert_eq!(request.send().await?.status(), reqwest::StatusCode::OK);
    assert_eq!(callback.requests.recv().await.unwrap().0, b"same body");
    assert!(
        tokio::time::timeout(Duration::from_millis(100), denied.accept())
            .await
            .is_err()
    );
    assert_eq!(lookup.call_count(), 3);
    Ok(())
}

#[tokio::test]
async fn tc1132_cancelled_send_releases_lease_before_refresh_commits() -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let lookup = Arc::new(TestLookup::default());
    lookup.set("db.test", &["192.2.1.1"]).await;
    let policy = Arc::new(EgressPolicy::for_test(
        vec!["db.test".into()],
        lookup.clone(),
        true,
    ));
    policy.refresh().await?;
    let url = Url::parse(&format!(
        "https://127.0.0.1:{}/",
        listener.local_addr()?.port()
    ))?;
    let destination = policy.resolve_url(&url).await?;
    let send = tokio::spawn(post(policy.clone(), destination, Duration::from_secs(10)).send());
    let (_stream, _) = tokio::time::timeout(Duration::from_secs(1), listener.accept()).await??;
    lookup.set("db.test", &["127.0.0.1"]).await;
    let mut refresh = {
        let policy = policy.clone();
        tokio::spawn(async move { policy.refresh().await })
    };
    let early = tokio::time::timeout(Duration::from_millis(100), &mut refresh).await;
    send.abort();
    assert!(send.await.unwrap_err().is_cancelled());
    assert!(
        early.is_err(),
        "a refresh may not invalidate an active send lease"
    );
    tokio::time::timeout(Duration::from_secs(1), refresh).await???;
    assert!(matches!(
        policy.resolve_url(&url).await,
        Err(EgressError::Forbidden)
    ));
    Ok(())
}

#[tokio::test]
async fn tc1132_cancellation_while_waiting_for_refresh_opens_no_connection() -> anyhow::Result<()> {
    use std::sync::atomic::Ordering;
    use test_support::GatedLookup;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let lookup = Arc::new(GatedLookup::default());
    lookup.answers.set("db.test", &["192.2.1.1"]).await;
    let policy = Arc::new(EgressPolicy::for_test(
        vec!["db.test".into()],
        lookup.clone(),
        true,
    ));
    policy.refresh().await?;
    let url = Url::parse(&format!(
        "https://127.0.0.1:{}/",
        listener.local_addr()?.port()
    ))?;
    let destination = policy.resolve_url(&url).await?;
    lookup.paused.store(true, Ordering::SeqCst);
    let refresh = {
        let policy = policy.clone();
        tokio::spawn(async move { policy.refresh().await })
    };
    tokio::time::timeout(Duration::from_secs(1), lookup.started.notified()).await?;
    let mut send = tokio::spawn(post(policy.clone(), destination, Duration::from_secs(10)).send());
    let early = tokio::time::timeout(Duration::from_millis(100), &mut send).await;
    send.abort();
    assert!(send.await.unwrap_err().is_cancelled());
    lookup.paused.store(false, Ordering::SeqCst);
    lookup.release.add_permits(1);
    refresh.await??;
    assert!(early.is_err());
    assert!(policy.resolve_url(&url).await.is_ok());
    assert!(
        tokio::time::timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn tc1132_total_send_deadline_includes_refresh_wait() -> anyhow::Result<()> {
    use std::sync::atomic::Ordering;
    use test_support::GatedLookup;
    let lookup = Arc::new(GatedLookup::default());
    lookup.answers.set("db.test", &["192.2.1.1"]).await;
    let policy = Arc::new(EgressPolicy::for_test(
        vec!["db.test".into()],
        lookup.clone(),
        false,
    ));
    policy.refresh().await?;
    let destination = policy
        .resolve_url(&Url::parse("https://198.51.0.1/")?)
        .await?;
    lookup.paused.store(true, Ordering::SeqCst);
    let refresh = {
        let policy = policy.clone();
        tokio::spawn(async move { policy.refresh().await })
    };
    lookup.started.notified().await;
    let start = Instant::now();
    let error = post(policy, destination, Duration::from_millis(250))
        .send()
        .await
        .unwrap_err();
    assert!(matches!(error, SendError::Timeout));
    assert_eq!(start.elapsed(), Duration::from_millis(250));
    lookup.paused.store(false, Ordering::SeqCst);
    lookup.release.add_permits(1);
    refresh.await??;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn tc1132_cancelled_refresh_preserves_fresh_state_but_never_lifts_stale_failure(
) -> anyhow::Result<()> {
    use std::sync::atomic::Ordering;
    use test_support::GatedLookup;
    let lookup = Arc::new(GatedLookup::default());
    lookup.answers.set("db.test", &["192.2.1.1"]).await;
    let policy = Arc::new(EgressPolicy::for_test(
        vec!["db.test".into()],
        lookup.clone(),
        false,
    ));
    policy.refresh().await?;
    lookup.paused.store(true, Ordering::SeqCst);
    let refresh = {
        let policy = policy.clone();
        tokio::spawn(async move { policy.refresh().await })
    };
    lookup.started.notified().await;
    refresh.abort();
    assert!(refresh.await.unwrap_err().is_cancelled());
    let callback = Url::parse("https://198.51.0.1/")?;
    assert!(policy.resolve_url(&callback).await.is_ok());
    tokio::time::advance(REFRESH_INTERVAL).await;
    lookup.paused.store(false, Ordering::SeqCst);
    lookup.answers.set("db.test", &[]).await;
    assert!(matches!(
        policy.resolve_url(&callback).await,
        Err(EgressError::Unavailable)
    ));
    Ok(())
}

#[tokio::test]
async fn tc1132_literal_tls_identity_and_healthy_delivery_survive_sealed_api() -> anyhow::Result<()>
{
    let mut callback = test_support::callback_server_for_host("127.0.0.1", 200, None).await?;
    let lookup = Arc::new(TestLookup::default());
    lookup.set("db.test", &["192.2.1.1"]).await;
    let policy = Arc::new(
        EgressPolicy::for_test(vec!["db.test".into()], lookup.clone(), true)
            .with_test_root(callback.certificate.clone()),
    );
    policy.refresh().await?;
    let url = Url::parse(&callback.url)?;
    let destination = policy.resolve_url(&url).await?;
    assert_eq!(
        post(policy.clone(), destination, Duration::from_secs(2))
            .body("before refresh")
            .send()
            .await?
            .status(),
        reqwest::StatusCode::OK
    );
    assert_eq!(callback.requests.recv().await.unwrap().0, b"before refresh");
    let destination = policy.resolve_url(&url).await?;
    let request =
        post(policy.clone(), destination, Duration::from_secs(2)).body("must not be sent");
    lookup.set("db.test", &["127.0.0.1"]).await;
    policy.refresh().await?;
    assert!(matches!(
        request.send().await,
        Err(SendError::Policy(EgressError::Forbidden))
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), callback.requests.recv())
            .await
            .is_err()
    );
    Ok(())
}
