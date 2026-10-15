use crate::{
    config::HooksConfig,
    egress::{self, EgressPolicy},
    TinyCloud,
};
use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::{collections::HashMap, sync::Arc, time::Duration};
use time::{Duration as TimeDuration, OffsetDateTime};
use tinycloud_core::ColumnEncryption;

type WebhookMac = Hmac<Sha256>;

const PRIMARY_SECRET_KEY_ID: &str = "primary";
const POLL_INTERVAL: Duration = Duration::from_secs(1);
const DISPATCH_BATCH_SIZE: u64 = 32;

#[derive(Clone)]
pub struct WebhookDispatcher {
    tinycloud: TinyCloud,
    encryption: ColumnEncryption,
    max_attempts: i64,
    timeout: Duration,
    egress: Arc<EgressPolicy>,
}

impl WebhookDispatcher {
    pub fn new(
        tinycloud: TinyCloud,
        config: HooksConfig,
        encryption: ColumnEncryption,
        egress: Arc<EgressPolicy>,
    ) -> Result<Self> {
        config.validate().map_err(anyhow::Error::msg)?;
        Ok(Self {
            tinycloud,
            encryption,
            max_attempts: config.webhook_max_attempts.max(1) as i64,
            timeout: Duration::from_secs(config.webhook_timeout_seconds.max(1)),
            egress,
        })
    }

    pub async fn dispatch_due_once(&self) -> Result<()> {
        let deliveries = self
            .tinycloud
            .list_due_webhook_deliveries(DISPATCH_BATCH_SIZE)
            .await
            .context("loading due webhook deliveries")?;

        // TC-991: re-derived once per subscription per pass and never carried across passes,
        // so a revocation or expiry applies by the next pass.
        let mut authority = HashMap::<String, bool>::new();
        for delivery in deliveries {
            if let Err(error) = self.dispatch_delivery(delivery, &mut authority).await {
                tracing::warn!(error = %error, "webhook delivery attempt failed");
            }
        }

        Ok(())
    }

    async fn dispatch_delivery(
        &self,
        delivery: tinycloud_core::db::PendingWebhookDelivery,
        authority: &mut HashMap<String, bool>,
    ) -> Result<()> {
        let current_attempt = delivery.attempts + 1;

        if !delivery.subscription_active {
            self.record_terminal_failure(delivery.id, current_attempt, "subscription inactive")
                .await?;
            return Ok(());
        }

        let authorized = match authority.get(&delivery.subscription_id) {
            Some(authorized) => *authorized,
            None => {
                let authorized = self
                    .tinycloud
                    .hook_register_authority_holds(
                        &delivery.subscriber_did,
                        &delivery.space_id,
                        &crate::hooks::hook_scope_path(
                            &delivery.target_service,
                            delivery.path_prefix.as_deref(),
                        ),
                        OffsetDateTime::now_utc(),
                    )
                    .await
                    .context("checking webhook subscription authority")?;
                if !authorized {
                    self.tinycloud
                        .deactivate_hook_subscription(&delivery.subscription_id)
                        .await
                        .context("deactivating webhook subscription whose authority lapsed")?;
                }
                authority.insert(delivery.subscription_id.clone(), authorized);
                authorized
            }
        };
        if !authorized {
            self.record_terminal_failure(
                delivery.id,
                current_attempt,
                "subscription authority lapsed",
            )
            .await?;
            return Ok(());
        }

        if delivery.secret_key_id != PRIMARY_SECRET_KEY_ID {
            self.record_terminal_failure(
                delivery.id,
                current_attempt,
                &format!(
                    "unsupported webhook secret key id {}",
                    delivery.secret_key_id
                ),
            )
            .await?;
            return Ok(());
        }

        let secret = match self.encryption.decrypt(&delivery.encrypted_secret) {
            Ok(secret) => secret,
            Err(error) => {
                self.record_terminal_failure(
                    delivery.id,
                    current_attempt,
                    &format!("secret decryption failed: {error}"),
                )
                .await?;
                return Ok(());
            }
        };
        let signature = sign_payload(&secret, delivery.payload_json.as_bytes())?;

        let destination = match crate::routes::hooks::validate_webhook_callback_url(
            &delivery.callback_url,
            &self.egress,
        )
        .await
        {
            Ok((_, destination)) => destination,
            Err(error) => {
                if error.is_retryable() {
                    self.record_retryable_failure(delivery.id, current_attempt, error.to_string())
                        .await?;
                } else {
                    self.record_terminal_failure(
                        delivery.id,
                        current_attempt,
                        &format!("callback URL rejected: {error}"),
                    )
                    .await?;
                }
                return Ok(());
            }
        };

        match egress::post(self.egress.clone(), destination, self.timeout)
            .header("Content-Type", "application/json")
            .header("X-TinyCloud-Delivery-Id", &delivery.id)
            .header("X-TinyCloud-Event-Id", &delivery.event_id)
            .header("X-TinyCloud-Subscription-Id", &delivery.subscription_id)
            .header("X-TinyCloud-Signature", signature)
            .body(delivery.payload_json)
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {
                self.tinycloud
                    .mark_webhook_delivery_delivered(&delivery.id, current_attempt)
                    .await
                    .context("marking webhook delivery delivered")?;
            }
            Ok(response) => {
                self.record_retryable_failure(
                    delivery.id,
                    current_attempt,
                    format!("callback returned {}", response.status()),
                )
                .await?;
            }
            Err(error) => {
                if error.is_retryable() {
                    self.record_retryable_failure(delivery.id, current_attempt, error.to_string())
                        .await?;
                } else {
                    self.record_terminal_failure(
                        delivery.id,
                        current_attempt,
                        &format!("callback URL rejected: {error}"),
                    )
                    .await?;
                }
            }
        }

        Ok(())
    }

    async fn record_terminal_failure(
        &self,
        delivery_id: String,
        attempts: i64,
        error: &str,
    ) -> Result<()> {
        self.tinycloud
            .mark_webhook_delivery_failed(&delivery_id, attempts, None, error.to_string(), true)
            .await
            .context("marking webhook delivery dead-letter")?;
        Ok(())
    }

    async fn record_retryable_failure(
        &self,
        delivery_id: String,
        attempts: i64,
        error: String,
    ) -> Result<()> {
        let next_attempt_number = attempts + 1;
        if next_attempt_number > self.max_attempts {
            self.tinycloud
                .mark_webhook_delivery_failed(&delivery_id, attempts, None, error, true)
                .await
                .context("marking exhausted webhook delivery dead-letter")?;
            return Ok(());
        }

        let next_attempt_at =
            OffsetDateTime::now_utc() + retry_delay_for_attempt(next_attempt_number);
        self.tinycloud
            .mark_webhook_delivery_failed(
                &delivery_id,
                attempts,
                Some(next_attempt_at),
                error,
                false,
            )
            .await
            .context("marking webhook delivery for retry")?;
        Ok(())
    }
}

pub fn spawn_webhook_dispatcher(dispatcher: WebhookDispatcher) {
    rocket::tokio::spawn(async move {
        loop {
            if let Err(error) = dispatcher.dispatch_due_once().await {
                tracing::warn!(error = %error, "webhook dispatcher loop failed");
            }

            rocket::tokio::time::sleep(POLL_INTERVAL).await;
        }
    });
}

fn retry_delay_for_attempt(attempt_number: i64) -> TimeDuration {
    match attempt_number {
        2 => TimeDuration::seconds(30),
        3 => TimeDuration::minutes(2),
        4 => TimeDuration::minutes(10),
        5.. => TimeDuration::hours(1),
        _ => TimeDuration::seconds(0),
    }
}

fn sign_payload(secret: &[u8], payload: &[u8]) -> Result<String> {
    let mut mac =
        WebhookMac::new_from_slice(secret).context("initializing webhook HMAC with secret")?;
    mac.update(payload);
    Ok(format!(
        "sha256={}",
        hex::encode(mac.finalize().into_bytes())
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::HooksConfig, storage::file_system::FileSystemConfig as NodeFileSystemConfig,
        TinyCloud,
    };
    use anyhow::Result;
    use hyper::{
        body::to_bytes,
        service::{make_service_fn, service_fn},
        Body, Request, Response, Server, StatusCode,
    };
    use reqwest::Url;
    use std::{convert::Infallible, net::TcpListener};
    use tempfile::TempDir;
    use tinycloud_core::{
        keys::StaticSecret,
        models::{hook_delivery, hook_subscription},
        sea_orm::{
            ActiveModelTrait, ActiveValue, ConnectOptions, Database, DatabaseConnection,
            EntityTrait, IntoActiveModel,
        },
        storage::either::Either,
        storage::StorageConfig as _,
    };

    const OWNER_DID: &str = "did:key:z6Mkpcii8rkJV79k3JV37Wm5utAU6WkRsziqXf6mpMs734vB";
    const SPACE_ID: &str = "tinycloud:key:z6Mkpcii8rkJV79k3JV37Wm5utAU6WkRsziqXf6mpMs734vB:files";

    async fn test_tinycloud() -> Result<(TinyCloud, DatabaseConnection, ColumnEncryption)> {
        let tempdir = TempDir::new()?;
        let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string())).await?;
        let storage = NodeFileSystemConfig::new(tempdir.path()).open().await?;
        let _persisted = tempdir.keep();
        let encryption = ColumnEncryption::new([9u8; 32]);
        let tinycloud = TinyCloud::new_with_encryption(
            db.clone().into(),
            Either::B(storage),
            StaticSecret::new(vec![0u8; 32]).unwrap(),
            Some(encryption.clone()),
        )
        .await?;
        Ok((tinycloud, db, encryption))
    }

    async fn spawn_callback_server(
        status: StatusCode,
    ) -> Result<(
        String,
        tokio::sync::mpsc::UnboundedReceiver<(String, String, String)>,
    )> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let make_service = make_service_fn(move |_| {
            let tx = tx.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |request: Request<Body>| {
                    let tx = tx.clone();
                    async move {
                        let signature = request
                            .headers()
                            .get("X-TinyCloud-Signature")
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or_default()
                            .to_string();
                        let event_id = request
                            .headers()
                            .get("X-TinyCloud-Event-Id")
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or_default()
                            .to_string();
                        let body = String::from_utf8(
                            to_bytes(request.into_body()).await.unwrap().to_vec(),
                        )
                        .unwrap();
                        let _ = tx.send((body, signature, event_id));
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(status)
                                .body(Body::from(""))
                                .unwrap(),
                        )
                    }
                }))
            }
        });

        rocket::tokio::spawn(async move {
            let server = Server::from_tcp(listener).unwrap().serve(make_service);
            let _ = server.await;
        });

        Ok((format!("http://{address}/hooks"), rx))
    }

    async fn insert_pending_delivery(
        db: &DatabaseConnection,
        encryption: &ColumnEncryption,
        callback_url: &str,
        attempts: i64,
    ) -> Result<String> {
        insert_subscription(db, encryption, callback_url, "sub_01", OWNER_DID).await?;
        insert_delivery(db, "sub_01", "delivery_01", attempts).await?;
        Ok("delivery_01".to_string())
    }

    async fn insert_subscription(
        db: &DatabaseConnection,
        encryption: &ColumnEncryption,
        callback_url: &str,
        subscription_id: &str,
        subscriber_did: &str,
    ) -> Result<()> {
        insert_subscription_in_space(
            db,
            encryption,
            callback_url,
            subscription_id,
            subscriber_did,
            SPACE_ID,
        )
        .await
    }

    async fn insert_subscription_in_space(
        db: &DatabaseConnection,
        encryption: &ColumnEncryption,
        callback_url: &str,
        subscription_id: &str,
        subscriber_did: &str,
        space_id: &str,
    ) -> Result<()> {
        hook_subscription::Entity::insert(hook_subscription::ActiveModel::from(
            hook_subscription::Model {
                id: subscription_id.to_string(),
                subscriber_did: subscriber_did.to_string(),
                space_id: space_id.to_string(),
                target_service: "kv".to_string(),
                path_prefix: Some("documents".to_string()),
                abilities_json: Some(
                    serde_json::to_string(&vec!["tinycloud.kv/put".to_string()]).unwrap(),
                ),
                callback_url: callback_url.to_string(),
                encrypted_secret: encryption.encrypt(b"hook-secret"),
                secret_key_id: PRIMARY_SECRET_KEY_ID.to_string(),
                active: true,
                created_at: "2026-04-09T00:00:00Z".to_string(),
            },
        ))
        .exec(db)
        .await?;
        Ok(())
    }

    async fn insert_delivery(
        db: &DatabaseConnection,
        subscription_id: &str,
        delivery_id: &str,
        attempts: i64,
    ) -> Result<()> {
        insert_delivery_in_space(db, subscription_id, delivery_id, attempts, SPACE_ID).await
    }

    async fn insert_delivery_in_space(
        db: &DatabaseConnection,
        subscription_id: &str,
        delivery_id: &str,
        attempts: i64,
        space_id: &str,
    ) -> Result<()> {
        hook_delivery::Entity::insert(hook_delivery::ActiveModel::from(hook_delivery::Model {
            id: delivery_id.to_string(),
            subscription_id: subscription_id.to_string(),
            event_id: delivery_id.replace("delivery", "event"),
            payload_json: serde_json::json!({"id": "event_01", "space": space_id}).to_string(),
            status: tinycloud_core::db::HOOK_DELIVERY_STATUS_PENDING.to_string(),
            attempts,
            next_attempt_at: None,
            last_error: None,
            created_at: "2026-04-09T00:00:00Z".to_string(),
            delivered_at: None,
        }))
        .exec(db)
        .await?;
        Ok(())
    }

    #[test]
    fn tc1132_later_attempts_keep_hour_backoff() {
        for attempt in [5, 6, 7, 10, i64::MAX] {
            assert_eq!(
                retry_delay_for_attempt(attempt),
                TimeDuration::hours(1),
                "{attempt}"
            );
        }
    }

    #[tokio::test]
    async fn tc1132_dispatcher_rejects_excessive_attempt_config() -> Result<()> {
        let (tinycloud, _, encryption) = test_tinycloud().await?;
        assert!(WebhookDispatcher::new(
            tinycloud,
            HooksConfig {
                webhook_max_attempts: 11,
                ..HooksConfig::default()
            },
            encryption,
            EgressPolicy::test_loopback()
        )
        .is_err());
        Ok(())
    }

    #[tokio::test]
    async fn tc1132_sixth_failure_schedules_hour_backoff() -> Result<()> {
        let (tinycloud, db, encryption) = test_tinycloud().await?;
        let (callback, _receiver) =
            spawn_callback_server(StatusCode::INTERNAL_SERVER_ERROR).await?;
        let id = insert_pending_delivery(&db, &encryption, &callback, 5).await?;
        let before = OffsetDateTime::now_utc();
        WebhookDispatcher::new(
            tinycloud,
            HooksConfig {
                webhook_max_attempts: 10,
                ..HooksConfig::default()
            },
            encryption,
            EgressPolicy::test_loopback(),
        )?
        .dispatch_due_once()
        .await?;
        let row = hook_delivery::Entity::find_by_id(id)
            .one(&db)
            .await?
            .unwrap();
        assert_eq!(
            row.status,
            tinycloud_core::db::HOOK_DELIVERY_STATUS_RETRYING
        );
        assert_eq!(row.attempts, 6);
        let next = OffsetDateTime::parse(
            row.next_attempt_at.as_deref().unwrap(),
            &time::format_description::well_known::Rfc3339,
        )?;
        assert!((next - before).whole_seconds() >= 3600);
        assert!((next - before).whole_seconds() <= 3602);
        Ok(())
    }
    #[tokio::test]
    async fn dispatches_due_delivery_and_marks_it_delivered() -> Result<()> {
        let (tinycloud, db, encryption) = test_tinycloud().await?;
        let (callback_url, mut receiver) = spawn_callback_server(StatusCode::OK).await?;
        let delivery_id = insert_pending_delivery(&db, &encryption, &callback_url, 0).await?;
        let dispatcher = WebhookDispatcher::new(
            tinycloud,
            HooksConfig::default(),
            encryption,
            EgressPolicy::test_loopback(),
        )?;

        dispatcher.dispatch_due_once().await?;

        let (body, signature, event_id) =
            tokio::time::timeout(Duration::from_secs(2), receiver.recv())
                .await?
                .expect("callback request");
        assert_eq!(
            body,
            serde_json::json!({"id": "event_01", "space": SPACE_ID}).to_string()
        );
        assert_eq!(event_id, "event_01");
        assert_eq!(signature, sign_payload(b"hook-secret", body.as_bytes())?);

        let delivery = hook_delivery::Entity::find_by_id(delivery_id)
            .one(&db)
            .await?
            .expect("delivery row");
        assert_eq!(
            delivery.status,
            tinycloud_core::db::HOOK_DELIVERY_STATUS_DELIVERED
        );
        assert_eq!(delivery.attempts, 1);
        assert!(delivery.delivered_at.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn retries_then_dead_letters_failed_delivery() -> Result<()> {
        let (tinycloud, db, encryption) = test_tinycloud().await?;
        let (callback_url, _receiver) =
            spawn_callback_server(StatusCode::INTERNAL_SERVER_ERROR).await?;
        let delivery_id = insert_pending_delivery(&db, &encryption, &callback_url, 0).await?;
        let dispatcher = WebhookDispatcher::new(
            tinycloud,
            HooksConfig {
                webhook_max_attempts: 2,
                ..HooksConfig::default()
            },
            encryption,
            EgressPolicy::test_loopback(),
        )?;

        dispatcher.dispatch_due_once().await?;

        let first = hook_delivery::Entity::find_by_id(delivery_id.clone())
            .one(&db)
            .await?
            .expect("first attempt row");
        assert_eq!(
            first.status,
            tinycloud_core::db::HOOK_DELIVERY_STATUS_RETRYING
        );
        assert_eq!(first.attempts, 1);
        assert!(first.next_attempt_at.is_some());

        let mut retryable = first.into_active_model();
        retryable.next_attempt_at = ActiveValue::Set(Some("2000-01-01T00:00:00Z".to_string()));
        retryable.update(&db).await?;

        dispatcher.dispatch_due_once().await?;

        let second = hook_delivery::Entity::find_by_id(delivery_id)
            .one(&db)
            .await?
            .expect("second attempt row");
        assert_eq!(
            second.status,
            tinycloud_core::db::HOOK_DELIVERY_STATUS_DEAD_LETTER
        );
        assert_eq!(second.attempts, 2);
        assert!(second.next_attempt_at.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn upgrade_migration_dead_letters_pending_deliveries_as_inactive() -> Result<()> {
        use tinycloud_core::{
            migrations::{m20261005_000000_deactivate_hook_subscriptions as deactivate, Migrator},
            sea_orm_migration::{MigrationName, MigratorTrait},
        };

        // A node on the previous release: subscription and delivery are live.
        let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string())).await?;
        let before_deactivation = Migrator::migrations()
            .iter()
            .position(|migration| migration.name() == deactivate::Migration.name())
            .expect("deactivation migration is registered")
            as u32;
        Migrator::up(&db, Some(before_deactivation)).await?;
        let encryption = ColumnEncryption::new([9u8; 32]);
        let (callback_url, mut receiver) = spawn_callback_server(StatusCode::OK).await?;
        let delivery_id = insert_pending_delivery(&db, &encryption, &callback_url, 0).await?;

        // Booting the upgraded node applies the remaining migration.
        let tempdir = TempDir::new()?;
        let storage = NodeFileSystemConfig::new(tempdir.path()).open().await?;
        let _persisted = tempdir.keep();
        let tinycloud = TinyCloud::new_with_encryption(
            db.clone().into(),
            Either::B(storage),
            StaticSecret::new(vec![0u8; 32]).unwrap(),
            Some(encryption.clone()),
        )
        .await?;
        let dispatcher = WebhookDispatcher::new(
            tinycloud,
            HooksConfig::default(),
            encryption,
            EgressPolicy::test_loopback(),
        )?;

        dispatcher.dispatch_due_once().await?;

        let delivery = hook_delivery::Entity::find_by_id(delivery_id)
            .one(&db)
            .await?
            .expect("delivery row");
        assert_eq!(
            delivery.status,
            tinycloud_core::db::HOOK_DELIVERY_STATUS_DEAD_LETTER
        );
        assert_eq!(
            delivery.last_error.as_deref(),
            Some("subscription inactive")
        );
        assert!(receiver.try_recv().is_err(), "no callback was sent");
        Ok(())
    }

    /// TC-951/TC-991: a dispatch pass on the production Postgres pool
    /// (`crate::connect_database`, no pre-acquire ping) when connections are
    /// lost. The subscriber holds `tinycloud.hooks/register` through a
    /// delegation, so every pass re-derives its authority from the
    /// database (#274). All pool traffic goes through an in-test TCP proxy
    /// that can reset the connection carrying any statement that binds the
    /// subscriber's DID, which only the authority check does.
    mod postgres_connection_loss {
        use super::*;
        use std::collections::BTreeMap;
        use std::{
            collections::BTreeSet,
            net::SocketAddr,
            sync::{
                atomic::{AtomicI64, AtomicU64, Ordering},
                Arc,
            },
        };
        use tinycloud_auth::{
            authorization::{HeaderEncode, TinyCloudDelegation},
            resolver::DID_METHODS,
            resource::SpaceId,
            ssi::{
                claims::jwt::NumericDate,
                dids::{DIDBuf, DIDURLBuf},
                jwk::JWK,
                ucan::Payload,
            },
            ucan_capabilities_object::{Ability, Capabilities},
        };
        use tinycloud_core::events::Delegation;
        use tinycloud_core::{
            db_pool::PoolRecoveryStats,
            models::key_revocation,
            sea_orm::{ConnectionTrait, DbBackend, Statement},
            RecoveringConnection,
        };
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpStream,
        };

        const IDLE_CONNECTIONS: usize = 8;

        fn postgres_url(test: &str) -> Option<String> {
            match std::env::var("TINYCLOUD_TEST_POSTGRES_URL") {
                Ok(url) if !url.trim().is_empty() => Some(url),
                _ => {
                    assert!(
                        std::env::var_os("CI").is_none(),
                        "{test} requires TINYCLOUD_TEST_POSTGRES_URL, which is unset in CI (TC-381)"
                    );
                    eprintln!("skipping {test}: TINYCLOUD_TEST_POSTGRES_URL is unset");
                    None
                }
            }
        }

        /// Resets the client connection that sends `marker`, before the
        /// server sees it. `cuts` is how many more such connections to reset;
        /// negative resets every one.
        struct Proxy {
            addr: SocketAddr,
            cuts: Arc<AtomicI64>,
            reset: Arc<AtomicU64>,
        }

        impl Proxy {
            async fn start(upstream: SocketAddr, marker: Vec<u8>) -> Self {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                let cuts = Arc::new(AtomicI64::new(0));
                let reset = Arc::new(AtomicU64::new(0));
                let marker = Arc::new(marker);
                let (task_cuts, task_reset) = (Arc::clone(&cuts), Arc::clone(&reset));
                tokio::spawn(async move {
                    while let Ok((client, _)) = listener.accept().await {
                        let Ok(server) = TcpStream::connect(upstream).await else {
                            continue;
                        };
                        tokio::spawn(pipe(
                            client,
                            server,
                            Arc::clone(&marker),
                            Arc::clone(&task_cuts),
                            Arc::clone(&task_reset),
                        ));
                    }
                });
                Self { addr, cuts, reset }
            }
        }

        async fn pipe(
            mut client: TcpStream,
            mut server: TcpStream,
            marker: Arc<Vec<u8>>,
            cuts: Arc<AtomicI64>,
            reset: Arc<AtomicU64>,
        ) {
            {
                let (mut client_read, mut client_write) = client.split();
                let (mut server_read, mut server_write) = server.split();
                let mut up = vec![0u8; 64 * 1024];
                let mut down = vec![0u8; 64 * 1024];
                loop {
                    tokio::select! {
                        read = client_read.read(&mut up) => {
                            let Ok(n @ 1..) = read else { break };
                            if up[..n].windows(marker.len()).any(|w| w == marker.as_slice())
                                && cuts
                                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                                        (left != 0).then_some(if left > 0 { left - 1 } else { left })
                                    })
                                    .is_ok()
                            {
                                reset.fetch_add(1, Ordering::SeqCst);
                                break;
                            }
                            if server_write.write_all(&up[..n]).await.is_err() {
                                break;
                            }
                        }
                        read = server_read.read(&mut down) => {
                            let Ok(n @ 1..) = read else { break };
                            if client_write.write_all(&down[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
            // RST, not FIN: the client sees the connection reset.
            #[allow(deprecated)]
            let _ = client.set_linger(Some(Duration::ZERO));
        }

        struct Fixture {
            admin: DatabaseConnection,
            /// Direct (unproxied) connection on the schema, for setup and
            /// inspection.
            setup: DatabaseConnection,
            schema: String,
            application_name: String,
            tinycloud: TinyCloud,
            encryption: ColumnEncryption,
            proxy: Proxy,
            holder: String,
            owner_key: JWK,
            owner_did: String,
            space_id: String,
            callback_url: String,
            callbacks: tokio::sync::mpsc::UnboundedReceiver<(String, String, String)>,
        }

        impl Fixture {
            async fn new(url: &str) -> Self {
                let admin = Database::connect(ConnectOptions::new(url.to_owned()))
                    .await
                    .unwrap();
                let unique = format!(
                    "{}_{}",
                    std::process::id(),
                    OffsetDateTime::now_utc().unix_timestamp_nanos() % 1_000_000_000_000
                );
                let schema = format!("tc991_dispatch_{unique}");
                let application_name = format!("tc991-dispatch-{unique}");
                admin
                    .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
                    .await
                    .unwrap();

                // Register a real owner-signed UCAN grant on this fixture's space.
                let owner_key = JWK::generate_ed25519().unwrap();
                let owner_did = DID_METHODS.generate(&owner_key, "key").unwrap().to_string();
                let space_id = SpaceId::new(
                    owner_did.parse::<DIDBuf>().unwrap(),
                    "files".parse().unwrap(),
                )
                .to_string();
                let holder = DID_METHODS
                    .generate(&JWK::generate_ed25519().unwrap(), "key")
                    .unwrap()
                    .to_string();
                let upstream = Url::parse(url).unwrap();
                let upstream_addr: SocketAddr = format!(
                    "{}:{}",
                    match upstream.host_str().unwrap_or("127.0.0.1") {
                        "localhost" => "127.0.0.1",
                        host => host,
                    },
                    upstream.port().unwrap_or(5432)
                )
                .parse()
                .expect("the test server is addressed by IP");
                let proxy = Proxy::start(upstream_addr, holder.clone().into_bytes()).await;

                let mut pool_url = upstream.clone();
                pool_url.set_port(Some(proxy.addr.port())).unwrap();
                pool_url.set_host(Some("127.0.0.1")).unwrap();
                pool_url
                    .query_pairs_mut()
                    .append_pair("application_name", &application_name)
                    .append_pair("options", &format!("-c search_path={schema}"));
                let mut config = crate::config::Config::default();
                config.storage.database = Some(pool_url.to_string());
                config.database.max_connections = 15;
                let conn = crate::connect_database(&config)
                    .await
                    .expect("production pool connects");
                assert!(conn.recovery().is_some());

                let tempdir = TempDir::new().unwrap();
                let storage = NodeFileSystemConfig::new(tempdir.path())
                    .open()
                    .await
                    .unwrap();
                let _persisted = tempdir.keep();
                let encryption = ColumnEncryption::new([9u8; 32]);
                let tinycloud = TinyCloud::new_with_encryption(
                    conn,
                    Either::B(storage),
                    StaticSecret::new(vec![0u8; 32]).unwrap(),
                    Some(encryption.clone()),
                )
                .await
                .unwrap();

                let mut setup_options = ConnectOptions::new(url.to_owned());
                setup_options
                    .max_connections(2)
                    .sqlx_logging(false)
                    .set_schema_search_path(schema.clone());
                let setup = Database::connect(setup_options).await.unwrap();
                grant_hook_register(&tinycloud, &owner_key, &owner_did, &holder, &space_id).await;
                let (callback_url, callbacks) =
                    spawn_callback_server(StatusCode::OK).await.unwrap();

                Self {
                    admin,
                    setup,
                    schema,
                    application_name,
                    tinycloud,
                    encryption,
                    proxy,
                    holder,
                    owner_key,
                    owner_did,
                    space_id,
                    callback_url,
                    callbacks,
                }
            }

            fn conn(&self) -> &RecoveringConnection {
                self.tinycloud.connection()
            }

            fn stats(&self) -> PoolRecoveryStats {
                self.conn().recovery().unwrap().stats()
            }

            fn dispatcher(&self) -> WebhookDispatcher {
                WebhookDispatcher::new(
                    self.tinycloud.clone(),
                    HooksConfig::default(),
                    self.encryption.clone(),
                    EgressPolicy::test_loopback(),
                )
                .unwrap()
            }

            /// A subscription of the delegated holder, with one pending
            /// delivery.
            async fn subscribe(&self, name: &str) -> (String, String) {
                let subscription = format!("sub_{name}");
                let delivery = format!("delivery_{name}");
                let subscriber = format!(
                    "{}#{}",
                    self.holder,
                    self.holder.strip_prefix("did:key:").unwrap()
                );
                insert_subscription_in_space(
                    &self.setup,
                    &self.encryption,
                    &self.callback_url,
                    &subscription,
                    &subscriber,
                    &self.space_id,
                )
                .await
                .unwrap();
                insert_delivery_in_space(&self.setup, &subscription, &delivery, 0, &self.space_id)
                    .await
                    .unwrap();
                (subscription, delivery)
            }

            async fn subscription_active(&self, subscription: &str) -> bool {
                hook_subscription::Entity::find_by_id(subscription.to_string())
                    .one(&self.setup)
                    .await
                    .unwrap()
                    .unwrap()
                    .active
            }

            async fn delivery(&self, delivery: &str) -> hook_delivery::Model {
                hook_delivery::Entity::find_by_id(delivery.to_string())
                    .one(&self.setup)
                    .await
                    .unwrap()
                    .unwrap()
            }

            async fn backends(&self) -> Vec<(i32, String)> {
                self.admin
                    .query_all(Statement::from_sql_and_values(
                        DbBackend::Postgres,
                        "SELECT pid, coalesce(state, '') AS state FROM pg_stat_activity \
                         WHERE application_name = $1",
                        [self.application_name.clone().into()],
                    ))
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|row| {
                        (
                            row.try_get::<i32>("", "pid").unwrap(),
                            row.try_get::<String>("", "state").unwrap(),
                        )
                    })
                    .collect()
            }

            /// Open `IDLE_CONNECTIONS` pooled connections and wait until
            /// every one is idle again; returns their backend pids.
            async fn fill_pool(&self) -> BTreeSet<i32> {
                let pool = self
                    .conn()
                    .sea_orm_connection()
                    .get_postgres_connection_pool();
                let mut held = Vec::new();
                for _ in 0..IDLE_CONNECTIONS {
                    held.push(pool.acquire().await.unwrap());
                }
                drop(held);
                for _ in 0..400 {
                    let backends = self.backends().await;
                    if pool.num_idle() as u32 == pool.size()
                        && backends.len() == pool.size() as usize
                        && backends.iter().all(|(_, state)| state == "idle")
                    {
                        return backends.into_iter().map(|(pid, _)| pid).collect();
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                panic!("pool did not settle: {:?}", self.backends().await);
            }

            async fn terminate(&self, pids: &BTreeSet<i32>) {
                for pid in pids {
                    self.admin
                        .execute(Statement::from_sql_and_values(
                            DbBackend::Postgres,
                            "SELECT pg_terminate_backend($1)",
                            [(*pid).into()],
                        ))
                        .await
                        .unwrap();
                }
                for _ in 0..400 {
                    if self
                        .backends()
                        .await
                        .iter()
                        .all(|(pid, _)| !pids.contains(pid))
                    {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                panic!("terminated backends linger");
            }

            async fn assert_delivered(&mut self, delivery: &str) {
                let (_, _, event_id) =
                    tokio::time::timeout(Duration::from_secs(5), self.callbacks.recv())
                        .await
                        .expect("callback within 5 s")
                        .expect("callback request");
                assert_eq!(event_id, delivery.replace("delivery", "event"));
                let row = self.delivery(delivery).await;
                assert_eq!(
                    row.status,
                    tinycloud_core::db::HOOK_DELIVERY_STATUS_DELIVERED
                );
                assert_eq!(row.attempts, 1);
            }

            async fn drop_schema(self) {
                self.conn()
                    .sea_orm_connection()
                    .get_postgres_connection_pool()
                    .close()
                    .await;
                self.setup.close().await.unwrap();
                self.admin
                    .execute_unprepared(&format!("DROP SCHEMA {} CASCADE", self.schema))
                    .await
                    .unwrap();
            }
        }

        fn delta(before: PoolRecoveryStats, after: PoolRecoveryStats) -> PoolRecoveryStats {
            PoolRecoveryStats {
                losses: after.losses - before.losses,
                retries: after.retries - before.retries,
                idempotent_retries: after.idempotent_retries - before.idempotent_retries,
                revalidations: after.revalidations - before.revalidations,
                revalidation_failures: after.revalidation_failures - before.revalidation_failures,
            }
        }

        async fn grant_hook_register(
            tinycloud: &TinyCloud,
            owner_key: &JWK,
            owner_did: &str,
            holder: &str,
            space_id: &str,
        ) {
            let space = space_id.parse::<SpaceId>().unwrap();
            let resource = space.to_resource(
                "hooks".parse().unwrap(),
                Some("kv/documents".parse().unwrap()),
                None,
                None,
            );
            let mut capabilities = Capabilities::new();
            capabilities.with_action(
                resource.as_uri(),
                "tinycloud.hooks/register".parse::<Ability>().unwrap(),
                [BTreeMap::<String, serde_json::Value>::new()],
            );
            let fragment = owner_did.rsplit_once(':').unwrap().1;
            let payload = Payload {
                issuer: format!("{owner_did}#{fragment}")
                    .parse::<DIDURLBuf>()
                    .unwrap(),
                audience: holder.parse::<DIDBuf>().unwrap(),
                not_before: None,
                expiration: NumericDate::try_from_seconds(
                    OffsetDateTime::now_utc().unix_timestamp() as f64 + 3600.0,
                )
                .unwrap(),
                nonce: Some(format!("tc1149-{holder}-{space_id}")),
                facts: Some(Vec::<serde_json::Value>::new()),
                proof: vec![],
                attenuation: capabilities,
            };
            let ucan = payload
                .sign(owner_key.get_algorithm().unwrap_or_default(), owner_key)
                .unwrap();
            let header = TinyCloudDelegation::Ucan(Box::new(ucan)).encode().unwrap();
            let delegation = Delegation::from_header_ser::<TinyCloudDelegation>(&header).unwrap();
            tinycloud
                .delegate(delegation)
                .await
                .unwrap_or_else(|_| panic!("signed hook grant must persist"));
        }
        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn tc1149_revoked_holder_stops_queued_webhook_but_owner_stays_live() {
            let Some(url) =
                postgres_url("tc1149_revoked_holder_stops_queued_webhook_but_owner_stays_live")
            else {
                return;
            };
            let mut fixture = Fixture::new(&url).await;
            let dispatcher = fixture.dispatcher();
            let (subscription, before) = fixture.subscribe("holder_before").await;
            dispatcher.dispatch_due_once().await.unwrap();
            fixture.assert_delivered(&before).await;

            let after = "delivery_holder_after";
            insert_delivery_in_space(&fixture.setup, &subscription, after, 0, &fixture.space_id)
                .await
                .unwrap();
            key_revocation::ActiveModel {
                target_did: ActiveValue::Set(fixture.holder.clone()),
                scope_key: ActiveValue::Set("global".to_string()),
                revoked_at: ActiveValue::Set(OffsetDateTime::now_utc().unix_timestamp()),
            }
            .insert(&fixture.setup)
            .await
            .unwrap();
            insert_subscription_in_space(
                &fixture.setup,
                &fixture.encryption,
                &fixture.callback_url,
                "sub_owner_control",
                &fixture.owner_did,
                &fixture.space_id,
            )
            .await
            .unwrap();
            insert_delivery_in_space(
                &fixture.setup,
                "sub_owner_control",
                "delivery_owner_control",
                0,
                &fixture.space_id,
            )
            .await
            .unwrap();

            dispatcher.dispatch_due_once().await.unwrap();
            fixture.assert_delivered("delivery_owner_control").await;
            assert!(
                fixture.callbacks.try_recv().is_err(),
                "revoked holder emitted a callback"
            );
            let denied = fixture.delivery(after).await;
            assert_eq!(
                denied.status,
                tinycloud_core::db::HOOK_DELIVERY_STATUS_DEAD_LETTER
            );
            assert!(!fixture.subscription_active(&subscription).await);
            fixture.drop_schema().await;
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn tc1149_revoked_owner_root_stops_queued_webhook() {
            let Some(url) = postgres_url("tc1149_revoked_owner_root_stops_queued_webhook") else {
                return;
            };
            let mut fixture = Fixture::new(&url).await;
            insert_subscription_in_space(
                &fixture.setup,
                &fixture.encryption,
                &fixture.callback_url,
                "sub_root",
                &fixture.owner_did,
                &fixture.space_id,
            )
            .await
            .unwrap();
            insert_delivery_in_space(
                &fixture.setup,
                "sub_root",
                "delivery_root_before",
                0,
                &fixture.space_id,
            )
            .await
            .unwrap();
            let dispatcher = fixture.dispatcher();
            dispatcher.dispatch_due_once().await.unwrap();
            fixture.assert_delivered("delivery_root_before").await;

            insert_delivery_in_space(
                &fixture.setup,
                "sub_root",
                "delivery_root_after",
                0,
                &fixture.space_id,
            )
            .await
            .unwrap();
            key_revocation::ActiveModel {
                target_did: ActiveValue::Set(fixture.owner_did.clone()),
                scope_key: ActiveValue::Set("global".to_string()),
                revoked_at: ActiveValue::Set(OffsetDateTime::now_utc().unix_timestamp()),
            }
            .insert(&fixture.setup)
            .await
            .unwrap();
            dispatcher.dispatch_due_once().await.unwrap();
            assert!(
                fixture.callbacks.try_recv().is_err(),
                "revoked root emitted a callback"
            );
            let denied = fixture.delivery("delivery_root_after").await;
            assert_eq!(
                denied.status,
                tinycloud_core::db::HOOK_DELIVERY_STATUS_DEAD_LETTER
            );
            assert!(!fixture.subscription_active("sub_root").await);
            fixture.drop_schema().await;
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn tc1149_space_revocation_stops_only_matching_webhook_space() {
            let Some(url) =
                postgres_url("tc1149_space_revocation_stops_only_matching_webhook_space")
            else {
                return;
            };
            let mut fixture = Fixture::new(&url).await;
            let other_space = SpaceId::new(
                fixture.owner_did.parse::<DIDBuf>().unwrap(),
                "other".parse().unwrap(),
            )
            .to_string();
            grant_hook_register(
                &fixture.tinycloud,
                &fixture.owner_key,
                &fixture.owner_did,
                &fixture.holder,
                &other_space,
            )
            .await;
            let (primary, before) = fixture.subscribe("scoped_before").await;
            let subscriber = format!(
                "{}#{}",
                fixture.holder,
                fixture.holder.strip_prefix("did:key:").unwrap()
            );
            insert_subscription_in_space(
                &fixture.setup,
                &fixture.encryption,
                &fixture.callback_url,
                "sub_other_space",
                &subscriber,
                &other_space,
            )
            .await
            .unwrap();
            let dispatcher = fixture.dispatcher();
            dispatcher.dispatch_due_once().await.unwrap();
            fixture.assert_delivered(&before).await;
            insert_delivery_in_space(
                &fixture.setup,
                "sub_other_space",
                "delivery_other_before",
                0,
                &other_space,
            )
            .await
            .unwrap();
            dispatcher.dispatch_due_once().await.unwrap();
            fixture.assert_delivered("delivery_other_before").await;

            insert_delivery_in_space(
                &fixture.setup,
                &primary,
                "delivery_scoped_after",
                0,
                &fixture.space_id,
            )
            .await
            .unwrap();
            insert_delivery_in_space(
                &fixture.setup,
                "sub_other_space",
                "delivery_other_after",
                0,
                &other_space,
            )
            .await
            .unwrap();
            key_revocation::ActiveModel {
                target_did: ActiveValue::Set(fixture.holder.clone()),
                scope_key: ActiveValue::Set(format!("space:{}", fixture.space_id)),
                revoked_at: ActiveValue::Set(OffsetDateTime::now_utc().unix_timestamp()),
            }
            .insert(&fixture.setup)
            .await
            .unwrap();
            dispatcher.dispatch_due_once().await.unwrap();
            fixture.assert_delivered("delivery_other_after").await;
            assert!(
                fixture.callbacks.try_recv().is_err(),
                "scoped-revoked holder emitted a callback"
            );
            assert_eq!(
                fixture.delivery("delivery_scoped_after").await.status,
                tinycloud_core::db::HOOK_DELIVERY_STATUS_DEAD_LETTER
            );
            assert!(!fixture.subscription_active(&primary).await);
            assert!(fixture.subscription_active("sub_other_space").await);
            fixture.drop_schema().await;
        }

        /// (a) Every idle pooled connection is terminated, then one pass
        /// runs: it delivers, the subscription stays active, and the pool
        /// recovered with one retry. (a') The authority check's own
        /// statement meets a reset connection once: it is retried in the
        /// same pass, which delivers.
        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn postgres_dispatch_recovers_lost_connections_during_reauthorization() {
            let Some(url) =
                postgres_url("postgres_dispatch_recovers_lost_connections_during_reauthorization")
            else {
                return;
            };
            let mut fixture = Fixture::new(&url).await;
            let dispatcher = fixture.dispatcher();

            // (a) mass loss before the pass.
            let (subscription, delivery) = fixture.subscribe("mass").await;
            let idle = fixture.fill_pool().await;
            let before = fixture.stats();
            fixture.terminate(&idle).await;
            dispatcher.dispatch_due_once().await.expect("the pass runs");
            let mass = delta(before, fixture.stats());
            fixture.assert_delivered(&delivery).await;
            assert!(fixture.subscription_active(&subscription).await);
            assert_eq!((mass.losses, mass.retries), (1, 1), "{mass:?}");
            assert!(mass.revalidation_failures >= 1, "{mass:?}");

            // (a') the authority check's statement is reset once.
            let (subscription, delivery) = fixture.subscribe("reauth").await;
            fixture.fill_pool().await;
            let before = fixture.stats();
            fixture.proxy.cuts.store(1, Ordering::SeqCst);
            dispatcher.dispatch_due_once().await.expect("the pass runs");
            let reauth = delta(before, fixture.stats());
            assert_eq!(fixture.proxy.reset.load(Ordering::SeqCst), 1);
            fixture.assert_delivered(&delivery).await;
            assert!(fixture.subscription_active(&subscription).await);
            assert_eq!((reauth.losses, reauth.retries), (1, 1), "{reauth:?}");
            eprintln!("dispatch after mass termination {mass:?}; after one reset authority check {reauth:?}");
            fixture.drop_schema().await;
        }

        /// (b) The authority check fails with a connection error on its
        /// first run and on its retry. The pass neither deactivates the
        /// subscription nor dead-letters the delivery, which stays pending
        /// with no attempt counted; the next pass, with the database
        /// reachable again, delivers it.
        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn postgres_dispatch_connection_failure_never_deactivates_or_dead_letters() {
            let Some(url) = postgres_url(
                "postgres_dispatch_connection_failure_never_deactivates_or_dead_letters",
            ) else {
                return;
            };
            let mut fixture = Fixture::new(&url).await;
            let dispatcher = fixture.dispatcher();
            let (subscription, delivery) = fixture.subscribe("unreachable").await;
            fixture.fill_pool().await;

            let before = fixture.stats();
            fixture.proxy.cuts.store(-1, Ordering::SeqCst);
            dispatcher.dispatch_due_once().await.expect("the pass runs");
            fixture.proxy.cuts.store(0, Ordering::SeqCst);
            let failed = delta(before, fixture.stats());
            assert_eq!(
                fixture.proxy.reset.load(Ordering::SeqCst),
                2,
                "the authority check ran, and was retried once"
            );
            assert_eq!((failed.losses, failed.retries), (2, 1), "{failed:?}");
            assert!(
                fixture.subscription_active(&subscription).await,
                "a connection error must not deactivate the subscription"
            );
            let row = fixture.delivery(&delivery).await;
            assert_eq!(
                row.status,
                tinycloud_core::db::HOOK_DELIVERY_STATUS_PENDING,
                "a connection error must not dead-letter the delivery"
            );
            assert_eq!(row.attempts, 0);
            assert!(
                fixture.callbacks.try_recv().is_err(),
                "no callback was sent"
            );

            dispatcher.dispatch_due_once().await.expect("the pass runs");
            fixture.assert_delivered(&delivery).await;
            assert!(fixture.subscription_active(&subscription).await);
            eprintln!("authority check unreachable for one pass: {failed:?}");
            fixture.drop_schema().await;
        }
    }
}
