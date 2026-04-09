use crate::{config::HooksConfig, TinyCloud};
use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use reqwest::Client;
use sha2::Sha256;
use std::time::Duration;
use time::{Duration as TimeDuration, OffsetDateTime};
use tinycloud_core::ColumnEncryption;

type WebhookMac = Hmac<Sha256>;

const PRIMARY_SECRET_KEY_ID: &str = "primary";
const POLL_INTERVAL: Duration = Duration::from_secs(1);
const DISPATCH_BATCH_SIZE: u64 = 32;

#[derive(Clone)]
pub struct WebhookDispatcher {
    tinycloud: TinyCloud,
    client: Client,
    encryption: ColumnEncryption,
    max_attempts: i64,
}

impl WebhookDispatcher {
    pub fn new(
        tinycloud: TinyCloud,
        config: HooksConfig,
        encryption: ColumnEncryption,
    ) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.webhook_timeout_seconds.max(1)))
            .build()
            .context("building webhook dispatcher HTTP client")?;

        Ok(Self {
            tinycloud,
            client,
            encryption,
            max_attempts: config.webhook_max_attempts.max(1) as i64,
        })
    }

    pub async fn dispatch_due_once(&self) -> Result<()> {
        let deliveries = self
            .tinycloud
            .list_due_webhook_deliveries(DISPATCH_BATCH_SIZE)
            .await
            .context("loading due webhook deliveries")?;

        for delivery in deliveries {
            if let Err(error) = self.dispatch_delivery(delivery).await {
                tracing::warn!(error = %error, "webhook delivery attempt failed");
            }
        }

        Ok(())
    }

    async fn dispatch_delivery(
        &self,
        delivery: tinycloud_core::db::PendingWebhookDelivery,
    ) -> Result<()> {
        let current_attempt = delivery.attempts + 1;

        if !delivery.subscription_active {
            self.record_terminal_failure(delivery.id, current_attempt, "subscription inactive")
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

        match self
            .client
            .post(&delivery.callback_url)
            .header("Content-Type", "application/json")
            .header("X-TinyCloud-Delivery-Id", &delivery.id)
            .header("X-TinyCloud-Event-Id", &delivery.event_id)
            .header("X-TinyCloud-Subscription-Id", &delivery.subscription_id)
            .header("X-TinyCloud-Signature", signature)
            .body(delivery.payload_json.clone())
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
                self.record_retryable_failure(delivery.id, current_attempt, error.to_string())
                    .await?;
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
        5 => TimeDuration::hours(1),
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

    async fn test_tinycloud() -> Result<(TinyCloud, DatabaseConnection, ColumnEncryption)> {
        let tempdir = TempDir::new()?;
        let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string())).await?;
        let storage = NodeFileSystemConfig::new(tempdir.path()).open().await?;
        let _persisted = tempdir.keep();
        let encryption = ColumnEncryption::new([9u8; 32]);
        let tinycloud = TinyCloud::new(
            db.clone(),
            Either::B(storage),
            StaticSecret::new(vec![0u8; 32]).unwrap(),
        )
        .await?
        .with_encryption(Some(encryption.clone()));
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
        let subscription_id = "sub_01".to_string();
        hook_subscription::Entity::insert(hook_subscription::ActiveModel::from(
            hook_subscription::Model {
                id: subscription_id.clone(),
                subscriber_did: "did:key:test".to_string(),
                space_id: "tinycloud:space".to_string(),
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

        let delivery_id = "delivery_01".to_string();
        hook_delivery::Entity::insert(hook_delivery::ActiveModel::from(hook_delivery::Model {
            id: delivery_id.clone(),
            subscription_id,
            event_id: "event_01".to_string(),
            payload_json: r#"{"id":"event_01","space":"tinycloud:space"}"#.to_string(),
            status: tinycloud_core::db::HOOK_DELIVERY_STATUS_PENDING.to_string(),
            attempts,
            next_attempt_at: None,
            last_error: None,
            created_at: "2026-04-09T00:00:00Z".to_string(),
            delivered_at: None,
        }))
        .exec(db)
        .await?;

        Ok(delivery_id)
    }

    #[tokio::test]
    async fn dispatches_due_delivery_and_marks_it_delivered() -> Result<()> {
        let (tinycloud, db, encryption) = test_tinycloud().await?;
        let (callback_url, mut receiver) = spawn_callback_server(StatusCode::OK).await?;
        let delivery_id = insert_pending_delivery(&db, &encryption, &callback_url, 0).await?;
        let dispatcher = WebhookDispatcher::new(tinycloud, HooksConfig::default(), encryption)?;

        dispatcher.dispatch_due_once().await?;

        let (body, signature, event_id) =
            tokio::time::timeout(Duration::from_secs(2), receiver.recv())
                .await?
                .expect("callback request");
        assert_eq!(body, r#"{"id":"event_01","space":"tinycloud:space"}"#);
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
}
