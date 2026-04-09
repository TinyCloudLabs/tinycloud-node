use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use time::OffsetDateTime;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplicationScope {
    Kv { prefix: Option<String> },
    Sql { db_name: String },
}

impl ReplicationScope {
    pub fn service(&self) -> &'static str {
        match self {
            Self::Kv { .. } => "kv",
            Self::Sql { .. } => "sql",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReplicationSessionRecord {
    pub requester_did: String,
    pub space_id: String,
    pub scope: ReplicationScope,
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicationSessionSummary {
    pub requester_did: String,
    pub space_id: String,
    pub service: String,
    pub prefix: Option<String>,
    pub db_name: Option<String>,
    pub expires_at: String,
}

impl ReplicationSessionSummary {
    pub fn from_record(record: &ReplicationSessionRecord) -> Self {
        let (prefix, db_name) = match &record.scope {
            ReplicationScope::Kv { prefix } => (prefix.clone(), None),
            ReplicationScope::Sql { db_name } => (None, Some(db_name.clone())),
        };

        Self {
            requester_did: record.requester_did.clone(),
            space_id: record.space_id.clone(),
            service: record.scope.service().to_string(),
            prefix,
            db_name,
            expires_at: record
                .expires_at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| record.expires_at.unix_timestamp().to_string()),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ReplicationSessionError {
    #[error("missing replication session token")]
    MissingToken,
    #[error("invalid or expired replication session token")]
    InvalidToken,
    #[error("replication session scope mismatch")]
    ScopeMismatch,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicationStatus {
    pub supported: bool,
    pub enabled: bool,
    pub roles_supported: Vec<&'static str>,
    pub roles_enabled: Vec<&'static str>,
    pub peer_serving: bool,
    pub recon: bool,
    pub auth_sync: bool,
    pub authored_fact_exchange: bool,
    pub notifications: bool,
    pub snapshots: bool,
}

impl Default for ReplicationStatus {
    fn default() -> Self {
        Self {
            supported: true,
            enabled: true,
            roles_supported: vec!["host", "replica"],
            roles_enabled: vec!["host"],
            peer_serving: true,
            recon: false,
            auth_sync: false,
            authored_fact_exchange: true,
            notifications: false,
            snapshots: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicationCapabilities {
    pub supported: bool,
    pub enabled: bool,
    pub peer_serving: bool,
    pub recon: bool,
    pub auth_sync: bool,
    pub authored_fact_exchange: bool,
    pub notifications: bool,
    pub snapshots: bool,
}

impl Default for ReplicationCapabilities {
    fn default() -> Self {
        Self {
            supported: false,
            enabled: false,
            peer_serving: false,
            recon: false,
            auth_sync: false,
            authored_fact_exchange: false,
            notifications: false,
            snapshots: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicationRouteStatus {
    pub route_mounted: bool,
    pub protocol_ready: bool,
    pub requires_auth: bool,
    pub endpoints: Vec<&'static str>,
    pub capabilities: ReplicationCapabilities,
}

impl Default for ReplicationRouteStatus {
    fn default() -> Self {
        Self {
            route_mounted: true,
            protocol_ready: true,
            requires_auth: true,
            endpoints: vec![
                "GET /replication/info",
                "POST /replication/session/open",
                "POST /replication/export",
                "POST /replication/reconcile",
                "POST /replication/sql/export",
                "POST /replication/sql/reconcile",
            ],
            capabilities: ReplicationCapabilities::from(ReplicationStatus::default()),
        }
    }
}

impl From<ReplicationStatus> for ReplicationCapabilities {
    fn from(status: ReplicationStatus) -> Self {
        Self {
            supported: status.supported,
            enabled: status.enabled,
            peer_serving: status.peer_serving,
            recon: status.recon,
            auth_sync: status.auth_sync,
            authored_fact_exchange: status.authored_fact_exchange,
            notifications: status.notifications,
            snapshots: status.snapshots,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReplicationService {
    status: ReplicationStatus,
    sessions: Arc<Mutex<HashMap<String, ReplicationSessionRecord>>>,
    session_ttl: Duration,
}

impl ReplicationService {
    pub fn new(status: ReplicationStatus) -> Self {
        Self::with_session_ttl(status, Duration::from_secs(600))
    }

    pub fn with_session_ttl(status: ReplicationStatus, session_ttl: Duration) -> Self {
        Self {
            status,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            session_ttl,
        }
    }

    pub fn status(&self) -> &ReplicationStatus {
        &self.status
    }

    pub fn route_status(&self) -> ReplicationRouteStatus {
        ReplicationRouteStatus {
            capabilities: self.status.clone().into(),
            ..ReplicationRouteStatus::default()
        }
    }

    pub fn open_session(
        &self,
        requester_did: String,
        space_id: String,
        scope: ReplicationScope,
    ) -> (String, ReplicationSessionRecord) {
        let now = OffsetDateTime::now_utc();
        let expires_at = now + time::Duration::seconds(self.session_ttl.as_secs() as i64);
        let token = new_session_token();
        let record = ReplicationSessionRecord {
            requester_did,
            space_id,
            scope,
            expires_at,
        };

        let mut sessions = self.sessions.lock().expect("replication sessions poisoned");
        prune_expired_sessions(&mut sessions, now);
        sessions.insert(token.clone(), record.clone());
        (token, record)
    }

    pub fn require_session(
        &self,
        token: Option<&str>,
        space_id: &str,
        scope: &ReplicationScope,
    ) -> Result<ReplicationSessionRecord, ReplicationSessionError> {
        let token = token.ok_or(ReplicationSessionError::MissingToken)?;
        let now = OffsetDateTime::now_utc();
        let mut sessions = self.sessions.lock().expect("replication sessions poisoned");
        prune_expired_sessions(&mut sessions, now);

        let record = sessions
            .get(token)
            .cloned()
            .ok_or(ReplicationSessionError::InvalidToken)?;

        if record.expires_at <= now {
            return Err(ReplicationSessionError::InvalidToken);
        }

        if record.space_id != space_id || !scope_is_subset(scope, &record.scope) {
            return Err(ReplicationSessionError::ScopeMismatch);
        }

        Ok(record)
    }
}

fn new_session_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn prune_expired_sessions(
    sessions: &mut HashMap<String, ReplicationSessionRecord>,
    now: OffsetDateTime,
) {
    sessions.retain(|_, record| record.expires_at > now);
}

fn normalize_scope_path(path: &str) -> &str {
    path.trim_matches('/')
}

fn scope_is_subset(requested: &ReplicationScope, granted: &ReplicationScope) -> bool {
    match (requested, granted) {
        (
            ReplicationScope::Kv {
                prefix: requested_prefix,
            },
            ReplicationScope::Kv {
                prefix: granted_prefix,
            },
        ) => match (requested_prefix.as_deref(), granted_prefix.as_deref()) {
            (_, None) => true,
            (None, Some(granted)) => normalize_scope_path(granted).is_empty(),
            (Some(requested), Some(granted)) => {
                let requested = normalize_scope_path(requested);
                let granted = normalize_scope_path(granted);
                granted.is_empty()
                    || requested == granted
                    || requested.starts_with(&format!("{granted}/"))
            }
        },
        (
            ReplicationScope::Sql { db_name: requested },
            ReplicationScope::Sql { db_name: granted },
        ) => granted.is_empty() || requested == granted,
        _ => false,
    }
}
