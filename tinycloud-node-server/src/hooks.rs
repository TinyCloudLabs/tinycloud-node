use crate::config::HooksConfig;
use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::sync::broadcast;

type TicketMac = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HookSubscription {
    pub space: String,
    pub service: String,
    #[serde(default)]
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub abilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HookTicketRequest {
    pub subscriptions: Vec<HookSubscription>,
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HookTicketResponse {
    pub ticket: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HookTicketClaims {
    pub v: u8,
    pub sub: String,
    pub scopes: Vec<HookSubscription>,
    pub iat: i64,
    pub exp: i64,
    pub parent_exp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WriteEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub id: String,
    pub space: String,
    pub service: String,
    pub ability: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub actor: String,
    pub epoch: String,
    pub event_index: u32,
    pub timestamp: String,
}

#[derive(Debug, Clone)]
pub struct WriteEventBus {
    sender: broadcast::Sender<WriteEvent>,
}

impl WriteEventBus {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity.max(1));
        Self { sender }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<WriteEvent> {
        self.sender.subscribe()
    }

    pub fn publish(&self, event: WriteEvent) {
        let _ = self.sender.send(event);
    }
}

#[derive(Debug)]
pub struct HookRuntime {
    bus: WriteEventBus,
    ticket_key: [u8; 32],
    config: HooksConfig,
    active_streams: Arc<AtomicUsize>,
}

impl HookRuntime {
    pub fn new(config: HooksConfig, ticket_key: [u8; 32]) -> Self {
        Self {
            bus: WriteEventBus::new(config.sse_broadcast_capacity),
            ticket_key,
            config,
            active_streams: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn config(&self) -> &HooksConfig {
        &self.config
    }

    pub fn bus(&self) -> &WriteEventBus {
        &self.bus
    }

    pub fn sign_ticket(&self, claims: &HookTicketClaims) -> Result<String, String> {
        let payload = serde_json::to_vec(claims).map_err(|e| e.to_string())?;
        let encoded_payload = encode_config(payload, URL_SAFE_NO_PAD);
        let mut mac = TicketMac::new_from_slice(&self.ticket_key).map_err(|e| e.to_string())?;
        mac.update(encoded_payload.as_bytes());
        let signature = mac.finalize().into_bytes();
        let encoded_signature = encode_config(signature, URL_SAFE_NO_PAD);
        Ok(format!("{encoded_payload}.{encoded_signature}"))
    }

    pub fn verify_ticket(&self, ticket: &str) -> Result<HookTicketClaims, String> {
        let (encoded_payload, encoded_signature) = ticket
            .split_once('.')
            .ok_or_else(|| "invalid ticket format".to_string())?;

        let mut mac = TicketMac::new_from_slice(&self.ticket_key).map_err(|e| e.to_string())?;
        mac.update(encoded_payload.as_bytes());
        let signature = decode_config(encoded_signature, URL_SAFE_NO_PAD)
            .map_err(|_| "invalid ticket signature".to_string())?;
        mac.verify_slice(&signature)
            .map_err(|_| "invalid ticket signature".to_string())?;

        let payload = decode_config(encoded_payload, URL_SAFE_NO_PAD)
            .map_err(|_| "invalid ticket payload".to_string())?;
        serde_json::from_slice(&payload).map_err(|_| "invalid ticket payload".to_string())
    }

    pub fn try_acquire_stream(&self) -> Result<HookStreamLease, String> {
        loop {
            let current = self.active_streams.load(Ordering::Relaxed);
            if current >= self.config.max_active_sse_streams {
                return Err("too many active hook streams".to_string());
            }
            if self
                .active_streams
                .compare_exchange(current, current + 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Ok(HookStreamLease {
                    active_streams: Arc::clone(&self.active_streams),
                });
            }
        }
    }
}

#[derive(Debug)]
pub struct HookStreamLease {
    active_streams: Arc<AtomicUsize>,
}

impl Drop for HookStreamLease {
    fn drop(&mut self) {
        self.active_streams.fetch_sub(1, Ordering::SeqCst);
    }
}

pub fn matches_scope(event: &WriteEvent, scope: &HookSubscription) -> bool {
    if event.space != scope.space || event.service != scope.service {
        return false;
    }

    if !scope.abilities.is_empty()
        && !scope
            .abilities
            .iter()
            .any(|ability| ability == &event.ability)
    {
        return false;
    }

    match (&scope.path_prefix, &event.path) {
        (None, _) => true,
        (Some(prefix), Some(path)) => path == prefix || path.starts_with(&format!("{prefix}/")),
        (Some(prefix), None) => prefix.is_empty(),
    }
}

pub fn normalize_path_prefix(path_prefix: Option<String>) -> Option<String> {
    path_prefix.and_then(|prefix| {
        let trimmed = prefix.trim_matches('/').to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

pub fn hook_scope_path(service: &str, path_prefix: Option<&str>) -> String {
    match path_prefix {
        Some(prefix) if !prefix.is_empty() => format!("{service}/{prefix}"),
        _ => service.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ticket_round_trip() {
        let runtime = HookRuntime::new(HooksConfig::default(), [7u8; 32]);
        let claims = HookTicketClaims {
            v: 1,
            sub: "did:key:test".to_string(),
            scopes: vec![HookSubscription {
                space: "tinycloud:space".to_string(),
                service: "kv".to_string(),
                path_prefix: Some("documents".to_string()),
                abilities: vec!["tinycloud.kv/put".to_string()],
            }],
            iat: 10,
            exp: 20,
            parent_exp: 20,
        };

        let ticket = runtime.sign_ticket(&claims).unwrap();
        let decoded = runtime.verify_ticket(&ticket).unwrap();
        assert_eq!(decoded.sub, claims.sub);
        assert_eq!(decoded.scopes, claims.scopes);
    }

    #[tokio::test]
    async fn scope_matching_uses_prefix_and_ability() {
        let event = WriteEvent {
            event_type: "write".to_string(),
            id: "epoch:0".to_string(),
            space: "tinycloud:space".to_string(),
            service: "kv".to_string(),
            ability: "tinycloud.kv/put".to_string(),
            path: Some("documents/123".to_string()),
            actor: "did:key:test".to_string(),
            epoch: "epoch".to_string(),
            event_index: 0,
            timestamp: "2026-01-01T00:00:00Z".to_string(),
        };

        assert!(matches_scope(
            &event,
            &HookSubscription {
                space: "tinycloud:space".to_string(),
                service: "kv".to_string(),
                path_prefix: Some("documents".to_string()),
                abilities: vec!["tinycloud.kv/put".to_string()],
            }
        ));

        assert!(!matches_scope(
            &event,
            &HookSubscription {
                space: "tinycloud:space".to_string(),
                service: "kv".to_string(),
                path_prefix: Some("other".to_string()),
                abilities: vec!["tinycloud.kv/put".to_string()],
            }
        ));

        assert!(!matches_scope(
            &event,
            &HookSubscription {
                space: "tinycloud:space".to_string(),
                service: "kv".to_string(),
                path_prefix: Some("document".to_string()),
                abilities: vec!["tinycloud.kv/put".to_string()],
            }
        ));

        let sql_event = WriteEvent {
            event_type: "write".to_string(),
            id: "epoch:0".to_string(),
            space: "tinycloud:space".to_string(),
            service: "sql".to_string(),
            ability: "tinycloud.sql/write".to_string(),
            path: Some("main.db/users".to_string()),
            actor: "did:key:test".to_string(),
            epoch: "epoch".to_string(),
            event_index: 0,
            timestamp: "2026-01-01T00:00:00Z".to_string(),
        };

        assert!(matches_scope(
            &sql_event,
            &HookSubscription {
                space: "tinycloud:space".to_string(),
                service: "sql".to_string(),
                path_prefix: Some("main.db".to_string()),
                abilities: vec!["tinycloud.sql/write".to_string()],
            }
        ));

        assert!(!matches_scope(
            &sql_event,
            &HookSubscription {
                space: "tinycloud:space".to_string(),
                service: "sql".to_string(),
                path_prefix: Some("other.db".to_string()),
                abilities: vec!["tinycloud.sql/write".to_string()],
            }
        ));
    }

    #[tokio::test]
    async fn write_event_serializes_with_type_field() {
        let event = WriteEvent {
            event_type: "write".to_string(),
            id: "epoch:0".to_string(),
            space: "tinycloud:space".to_string(),
            service: "kv".to_string(),
            ability: "tinycloud.kv/put".to_string(),
            path: Some("documents/123".to_string()),
            actor: "did:key:test".to_string(),
            epoch: "epoch".to_string(),
            event_index: 0,
            timestamp: "2026-01-01T00:00:00Z".to_string(),
        };

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json.get("type").and_then(|v| v.as_str()), Some("write"));
    }
}
