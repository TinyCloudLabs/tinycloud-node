use crate::{
    allow_list::SpaceAllowListService,
    storage::{file_system::FileSystemConfig, s3::S3BlockConfig},
    BlockConfig, BlockStage,
};
use base64::{decode_config, URL_SAFE_NO_PAD};
use rocket::data::ByteUnit;
use serde::{Deserialize, Serialize};
use serde_with::{
    base64::{Base64, UrlSafe},
    formats::Unpadded,
    serde_as, FromInto,
};
use std::{fs, path::PathBuf};
use tinycloud_core::keys::StaticSecret;

#[derive(Serialize, Deserialize, Debug, Default, Clone, Hash, PartialEq, Eq)]
pub struct Config {
    pub log: Logging,
    pub storage: Storage,
    pub spaces: SpacesConfig,
    #[serde(default)]
    pub hooks: HooksConfig,
    #[serde(default)]
    pub tc_bench: TcBenchConfig,
    pub relay: Relay,
    #[serde(default)]
    pub telemetry: Telemetry,
    pub prometheus: Prometheus,
    pub cors: bool,
    #[serde(default)]
    pub keys: Keys,
    #[serde(default)]
    pub tee: TeeConfig,
    #[serde(default)]
    pub public_spaces: PublicSpacesConfig,
    #[serde(default)]
    pub share_email: ShareEmailConfig,
}

/// Production exact-email composition.  The capability remains unavailable
/// until every trust/key/dependency field is configured; there are no fake
/// adapters or development credentials in this configuration surface.
#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct ShareEmailConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_share_target_origin")]
    pub target_origin: String,
    #[serde(default = "default_share_node_audience")]
    pub node_audience: String,
    #[serde(default = "default_share_return_origin")]
    pub return_origin: String,
    /// The only browser origin allowed to call the node's share-email API.
    /// This is deliberately a list so the deployed value is visible in the
    /// configuration and cannot accidentally become a wildcard.
    #[serde(default = "default_share_allowed_origins")]
    pub allowed_origins: Vec<String>,
    #[serde(default = "default_share_node_signing_kid")]
    pub node_signing_kid: String,
    #[serde(default = "default_share_invitation_kid")]
    pub invitation_kid: String,
    #[serde(default)]
    pub invitation_public_key: Option<String>,
    #[serde(default = "default_share_issuer_did")]
    pub issuer_did: String,
    #[serde(default = "default_share_issuer_vct")]
    pub issuer_vct: String,
    #[serde(default = "default_share_issuer_kid")]
    pub issuer_kid: String,
    #[serde(default = "default_share_issuer_key_version")]
    pub issuer_key_version: u64,
    #[serde(default)]
    pub issuer_public_key: Option<String>,
    /// Operator-delivered owner-signed authority material. A missing or
    /// unreadable source keeps the capability unavailable.
    #[serde(default)]
    pub authority_material_path: Option<String>,
    /// The mounted, public environment trust bundle shared with Share and
    /// OpenCredentials. Individual trust fields are legacy test overrides;
    /// production composition resolves them from this file.
    #[serde(default)]
    pub trust_bundle_path: Option<String>,
    /// Optional legacy assertions for the shared bundle's service origins.
    /// They are never a source of production trust.
    #[serde(default)]
    pub share_origin: Option<String>,
    #[serde(default)]
    pub registry_origin: Option<String>,
    #[serde(default)]
    pub credentials_origin: Option<String>,
    #[serde(default)]
    pub postgres_tls: ShareEmailPostgresTlsConfig,
    #[serde(default = "default_share_readiness_max_age")]
    pub readiness_max_age_seconds: u64,
    #[serde(default = "default_share_clock_skew")]
    pub clock_skew_seconds: i64,
    #[serde(default = "default_share_challenge_ttl")]
    pub challenge_ttl_seconds: u64,
    #[serde(default = "default_share_space_name")]
    pub space_name: String,
}

fn default_share_target_origin() -> String {
    String::new()
}
fn default_share_node_audience() -> String {
    String::new()
}
fn default_share_return_origin() -> String {
    "https://share.tinycloud.xyz".to_owned()
}
fn default_share_allowed_origins() -> Vec<String> {
    vec![default_share_return_origin()]
}
fn default_share_node_signing_kid() -> String {
    String::new()
}
fn default_share_invitation_kid() -> String {
    String::new()
}
fn default_share_issuer_did() -> String {
    String::new()
}
fn default_share_issuer_vct() -> String {
    tinycloud_auth::share_email_evidence::EMAIL_VCT.to_owned()
}
fn default_share_issuer_kid() -> String {
    String::new()
}
fn default_share_issuer_key_version() -> u64 {
    1
}
fn default_share_clock_skew() -> i64 {
    30
}
fn default_share_challenge_ttl() -> u64 {
    120
}
fn default_share_space_name() -> String {
    "default".to_owned()
}
fn default_share_readiness_max_age() -> u64 {
    300
}

/// PostgreSQL TLS settings used by the enabled share-email runtime.  The
/// default is intentionally disabled so existing SQLite development nodes do
/// not change behavior; a PostgreSQL-backed enabled deployment must set the
/// exact `verify-full` mode and a CA bundle path.
#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct ShareEmailPostgresTlsConfig {
    #[serde(default = "default_share_postgres_sslmode")]
    pub sslmode: String,
    #[serde(default)]
    pub root_cert_path: Option<String>,
}

fn default_share_postgres_sslmode() -> String {
    "disabled".to_owned()
}

impl Default for ShareEmailPostgresTlsConfig {
    fn default() -> Self {
        Self {
            sslmode: default_share_postgres_sslmode(),
            root_cert_path: None,
        }
    }
}

impl Default for ShareEmailConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            target_origin: default_share_target_origin(),
            node_audience: default_share_node_audience(),
            return_origin: default_share_return_origin(),
            allowed_origins: default_share_allowed_origins(),
            node_signing_kid: default_share_node_signing_kid(),
            invitation_kid: default_share_invitation_kid(),
            invitation_public_key: None,
            issuer_did: default_share_issuer_did(),
            issuer_vct: default_share_issuer_vct(),
            issuer_kid: default_share_issuer_kid(),
            issuer_key_version: default_share_issuer_key_version(),
            issuer_public_key: None,
            authority_material_path: None,
            trust_bundle_path: None,
            share_origin: None,
            registry_origin: None,
            credentials_origin: None,
            postgres_tls: ShareEmailPostgresTlsConfig::default(),
            readiness_max_age_seconds: default_share_readiness_max_age(),
            clock_skew_seconds: default_share_clock_skew(),
            challenge_ttl_seconds: default_share_challenge_ttl(),
            space_name: default_share_space_name(),
        }
    }
}

impl ShareEmailConfig {
    pub fn resolve_trust_bundle(&self) -> Result<Self, &'static str> {
        if !self.enabled {
            return Ok(self.clone());
        }
        let Some(path) = self.trust_bundle_path.as_deref() else {
            if allows_hermetic_fixture() {
                return Ok(self.clone());
            }
            return Err("share email trust bundle is required");
        };
        let bytes = fs::read(path).map_err(|_| "share email trust bundle is unreadable")?;
        if bytes.len() > 64 * 1024 {
            return Err("share email trust bundle is too large");
        }
        let bundle: ShareEmailTrustBundle =
            serde_json::from_slice(&bytes).map_err(|_| "share email trust bundle is invalid")?;
        bundle.validate()?;
        bundle.matches_config(self)?;
        let mut resolved = self.clone();
        resolved.target_origin = bundle.node_origin;
        resolved.node_audience = bundle.node_audience;
        resolved.return_origin = bundle.return_origin.clone();
        resolved.allowed_origins = vec![bundle.return_origin];
        resolved.node_signing_kid = bundle.node_invitation_kid.clone();
        resolved.invitation_kid = bundle.node_invitation_kid;
        resolved.invitation_public_key = Some(bundle.node_invitation_public_key);
        resolved.issuer_did = bundle.issuer_did;
        resolved.issuer_vct = bundle.issuer_vct;
        resolved.issuer_kid = bundle.issuer_kid;
        resolved.issuer_key_version = bundle.issuer_key_version as u64;
        resolved.issuer_public_key = Some(bundle.issuer_public_key);
        Ok(resolved)
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if !self.enabled {
            return Ok(());
        }
        self.resolve_trust_bundle()?.validate_fields()
    }

    fn validate_fields(&self) -> Result<(), &'static str> {
        if !allows_hermetic_fixture() && uses_fixture_identity(self) {
            return Err("share email production trust bundle contains a fixture identity");
        }
        if tinycloud_core::share_email::TargetOrigin::parse(self.target_origin.clone()).is_err()
            || tinycloud_core::share_email::TargetOrigin::parse(self.return_origin.clone()).is_err()
            || self.allowed_origins.len() != 1
            || self.allowed_origins.first() != Some(&self.return_origin)
            || self.allowed_origins.iter().any(|origin| {
                origin == "*"
                    || tinycloud_core::share_email::TargetOrigin::parse(origin.clone()).is_err()
            })
            || tinycloud_core::share_email::Did::parse(self.node_audience.clone()).is_err()
            || !origin_audience_matches(&self.target_origin, &self.node_audience)
            || self.node_signing_kid != self.invitation_kid
            || !canonical_kid_matches(&self.node_signing_kid, &self.node_audience)
            || self.issuer_did.is_empty()
            || self.issuer_did != tinycloud_auth::share_email_evidence::OPEN_CREDENTIALS_ISSUER_DID
            || self.issuer_vct != tinycloud_auth::share_email_evidence::EMAIL_VCT
            || !canonical_kid_matches(&self.issuer_kid, &self.issuer_did)
            || self.issuer_key_version == 0
            || self.clock_skew_seconds < 0
            || self.clock_skew_seconds > 300
            || self.challenge_ttl_seconds == 0
            || self.challenge_ttl_seconds > 120
            || self.invitation_public_key.is_none()
            || self.issuer_public_key.is_none()
            || self.authority_material_path.is_none()
            || self
                .authority_material_path
                .as_deref()
                .is_some_and(|path| path.trim().is_empty())
            || self.readiness_max_age_seconds == 0
            || self.readiness_max_age_seconds > 300
        {
            return Err("share email configuration is incomplete");
        }
        Ok(())
    }

    /// Validate settings that depend on the resolved node database.  This is
    /// called before any connection is opened, so an enabled PostgreSQL
    /// deployment cannot accidentally start with an unauthenticated TLS mode
    /// or a missing CA bundle.
    pub fn validate_for_database(&self, database: &str) -> Result<(), &'static str> {
        self.validate()?;
        if !self.enabled {
            return Ok(());
        }
        if is_postgres_database(database) {
            if self.postgres_tls.sslmode != "verify-full"
                || !database_has_query(database, "sslmode", "verify-full")
                || database_has_forbidden_query(database)
                || self.postgres_tls.root_cert_path.is_none()
            {
                return Err("share email PostgreSQL requires sslmode=verify-full and a CA bundle");
            }
            let root_cert = self
                .postgres_tls
                .root_cert_path
                .as_deref()
                .unwrap_or_default();
            if root_cert.trim().is_empty()
                || !fs::metadata(root_cert)
                    .map(|metadata| metadata.is_file())
                    .unwrap_or(false)
            {
                return Err("share email PostgreSQL CA bundle is missing");
            }
        } else if self.postgres_tls.sslmode != "disabled"
            || self.postgres_tls.root_cert_path.is_some()
        {
            return Err("share email PostgreSQL TLS settings require a PostgreSQL database");
        }
        Ok(())
    }
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct ShareEmailTrustBundle {
    version: String,
    share_origin: String,
    return_origin: String,
    registry_origin: String,
    credentials_origin: String,
    node_origin: String,
    node_audience: String,
    node_invitation_kid: String,
    node_invitation_public_key: String,
    node_key_version: u32,
    node_enabled: bool,
    issuer_did: String,
    issuer_vct: String,
    issuer_kid: String,
    issuer_public_key: String,
    issuer_key_version: u32,
    issuer_enabled: bool,
}

impl ShareEmailTrustBundle {
    fn validate(&self) -> Result<(), &'static str> {
        let fixture_origin = allows_hermetic_fixture()
            && canonical_https_origin_with_optional_port(&self.share_origin);
        let fixture_node_origin = allows_hermetic_fixture()
            && canonical_https_origin_with_optional_port(&self.node_origin);
        if self.version != "tinycloud.share-email-trust-bundle/v1"
            || (!fixture_origin && self.share_origin != "https://share.tinycloud.xyz")
            || self.return_origin != self.share_origin
            || !canonical_https_origin(&self.registry_origin)
            || self.credentials_origin != "https://witness.credentials.org"
            || (!canonical_https_origin(&self.node_origin) && !fixture_node_origin)
            || self.node_audience
                != format!(
                    "did:web:{}",
                    host_of(&self.node_origin).ok_or("trust bundle node origin")?
                )
            || self.node_invitation_kid
                != format!(
                    "{}#invitation-key-{}",
                    self.node_audience, self.node_key_version
                )
            || self.node_key_version == 0
            || !self.node_enabled
            || self.issuer_did != "did:web:issuer.credentials.org"
            || self.issuer_vct != "opencredentials.email/v1"
            || !canonical_kid_matches(&self.issuer_kid, &self.issuer_did)
            || self.issuer_key_version == 0
            || !self.issuer_enabled
            || !canonical_key(&self.node_invitation_public_key)
            || !canonical_key(&self.issuer_public_key)
            || (!allows_hermetic_fixture() && self.contains_fixture_material())
        {
            return Err("share email trust bundle is inconsistent");
        }
        Ok(())
    }

    fn matches_config(&self, config: &ShareEmailConfig) -> Result<(), &'static str> {
        let matches = config.target_origin.is_empty() || config.target_origin == self.node_origin;
        let matches = matches
            && (config.node_audience.is_empty() || config.node_audience == self.node_audience)
            && (config.return_origin == default_share_return_origin()
                || config.return_origin == self.return_origin)
            && (config.allowed_origins == default_share_allowed_origins()
                || config.allowed_origins == vec![self.return_origin.clone()])
            && (config.node_signing_kid.is_empty()
                || config.node_signing_kid == self.node_invitation_kid)
            && (config.invitation_kid.is_empty()
                || config.invitation_kid == self.node_invitation_kid)
            && (config.invitation_public_key.is_none()
                || config.invitation_public_key.as_deref()
                    == Some(self.node_invitation_public_key.as_str()))
            && (config.issuer_did.is_empty() || config.issuer_did == self.issuer_did)
            && config.issuer_vct == self.issuer_vct
            && (config.issuer_kid.is_empty() || config.issuer_kid == self.issuer_kid)
            && (config.issuer_key_version == default_share_issuer_key_version()
                || config.issuer_key_version == self.issuer_key_version as u64)
            && (config.issuer_public_key.is_none()
                || config.issuer_public_key.as_deref() == Some(self.issuer_public_key.as_str()))
            && config
                .share_origin
                .as_deref()
                .is_none_or(|value| value == self.share_origin)
            && config
                .registry_origin
                .as_deref()
                .is_none_or(|value| value == self.registry_origin)
            && config
                .credentials_origin
                .as_deref()
                .is_none_or(|value| value == self.credentials_origin);
        if matches {
            Ok(())
        } else {
            Err("share email trust bundle disagrees with configured trust")
        }
    }

    fn contains_fixture_material(&self) -> bool {
        [
            &self.share_origin,
            &self.return_origin,
            &self.registry_origin,
            &self.credentials_origin,
            &self.node_origin,
            &self.node_audience,
            &self.node_invitation_kid,
            &self.issuer_did,
            &self.issuer_vct,
            &self.issuer_kid,
        ]
        .into_iter()
        .any(|value| contains_placeholder(value))
            || is_fixture_public_key(&self.node_invitation_public_key)
            || is_fixture_public_key(&self.issuer_public_key)
    }
}

fn canonical_https_origin(value: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(value) else {
        return false;
    };
    url.scheme() == "https"
        && url.origin().ascii_serialization() == value
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
}

fn canonical_https_origin_with_optional_port(value: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(value) else {
        return false;
    };
    url.scheme() == "https"
        && url.origin().ascii_serialization() == value
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none()
}

fn host_of(value: &str) -> Option<String> {
    Some(reqwest::Url::parse(value).ok()?.host_str()?.to_owned())
}

fn canonical_key(value: &str) -> bool {
    let Ok(bytes) = decode_config(value, URL_SAFE_NO_PAD) else {
        return false;
    };
    bytes.len() == 32 && base64::encode_config(bytes, URL_SAFE_NO_PAD) == value
}

fn contains_placeholder(value: &str) -> bool {
    value.to_ascii_lowercase().contains("example")
        || value.to_ascii_lowercase().contains("localhost")
        || value.to_ascii_lowercase().contains("127.0.0.1")
        || value.to_ascii_lowercase().contains("fixture")
        || value.to_ascii_lowercase().contains("placeholder")
        || value.to_ascii_lowercase().contains("seed")
        || value.to_ascii_lowercase().contains("test")
}

#[cfg(feature = "mounted-fixture")]
fn allows_hermetic_fixture() -> bool {
    true
}

#[cfg(not(feature = "mounted-fixture"))]
fn allows_hermetic_fixture() -> bool {
    false
}

fn uses_fixture_identity(config: &ShareEmailConfig) -> bool {
    is_placeholder_domain(&config.target_origin)
        || is_placeholder_domain(&config.node_audience)
        || is_placeholder_domain(&config.issuer_did)
        || config
            .invitation_public_key
            .as_deref()
            .is_some_and(is_fixture_public_key)
        || config
            .issuer_public_key
            .as_deref()
            .is_some_and(is_fixture_public_key)
}

fn is_placeholder_domain(value: &str) -> bool {
    let host = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("did:web:"))
        .unwrap_or(value)
        .split(['/', ':'])
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    host == "localhost"
        || host.ends_with(".example")
        || host.ends_with(".invalid")
        || host.ends_with(".test")
}

fn is_repeated_test_key(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return false;
    };
    let Ok(bytes) = decode_config(value, URL_SAFE_NO_PAD) else {
        return false;
    };
    bytes.len() == 32 && bytes.windows(2).all(|pair| pair[0] == pair[1])
}

fn is_fixture_public_key(value: &str) -> bool {
    const FROZEN_NODE_PUBLIC_KEY: &str = "IVL40Zt5HSRFMkLhXy6rbLfP-ntqXtMAl5YOBpiB2xI";
    const FROZEN_ISSUER_PUBLIC_KEY: &str = "Ivwpd5Lwtv_Av8_bftsMCqFOAlo2XsDjQuhuOCnLdLY";
    value == FROZEN_NODE_PUBLIC_KEY
        || value == FROZEN_ISSUER_PUBLIC_KEY
        || is_repeated_test_key(Some(value))
}

fn canonical_kid_matches(kid: &str, did: &str) -> bool {
    let Some((prefix, fragment)) = kid.split_once('#') else {
        return false;
    };
    prefix == did
        && !fragment.is_empty()
        && !fragment.contains('#')
        && !fragment.chars().any(char::is_whitespace)
}

fn origin_audience_matches(origin: &str, audience: &str) -> bool {
    let Some(host) = origin
        .strip_prefix("https://")
        .and_then(|value| value.split_once(':').map(|(host, _)| host).or(Some(value)))
    else {
        return false;
    };
    audience == format!("did:web:{host}")
}

fn is_postgres_database(database: &str) -> bool {
    database.starts_with("postgres://") || database.starts_with("postgresql://")
}

fn database_has_query(database: &str, expected_key: &str, expected_value: &str) -> bool {
    let Some((_, query)) = database.split_once('?') else {
        return false;
    };
    let mut found = None;
    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        if key == expected_key {
            if found.is_some() {
                return false;
            }
            found = Some(value);
        }
    }
    found == Some(expected_value)
}

fn database_has_forbidden_query(database: &str) -> bool {
    const FORBIDDEN: [&str; 6] = [
        "sslrootcert",
        "sslcert",
        "sslkey",
        "sslpassword",
        "sslcrl",
        "hostaddr",
    ];
    database.split_once('?').is_some_and(|(_, query)| {
        query.split('&').any(|pair| {
            pair.split_once('=')
                .is_some_and(|(key, _)| FORBIDDEN.contains(&key))
        })
    })
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct PublicSpacesConfig {
    #[serde(default = "default_rate_limit_per_minute")]
    pub rate_limit_per_minute: u32,
    #[serde(default = "default_rate_limit_burst")]
    pub rate_limit_burst: u32,
    #[serde(default = "default_public_storage_limit")]
    pub storage_limit: ByteUnit,
}

fn default_rate_limit_per_minute() -> u32 {
    60
}

fn default_rate_limit_burst() -> u32 {
    10
}

fn default_public_storage_limit() -> ByteUnit {
    ByteUnit::Mebibyte(10)
}

impl Default for PublicSpacesConfig {
    fn default() -> Self {
        Self {
            rate_limit_per_minute: default_rate_limit_per_minute(),
            rate_limit_burst: default_rate_limit_burst(),
            storage_limit: default_public_storage_limit(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct TcBenchConfig {
    #[serde(default = "default_tc_bench_region")]
    pub region: String,
    #[serde(default)]
    pub worker_bundle_sha256: Option<String>,
    #[serde(default)]
    pub wasm_bundle_sha256: Option<String>,
}

fn default_tc_bench_region() -> String {
    "phala-cvm".to_string()
}

impl Default for TcBenchConfig {
    fn default() -> Self {
        Self {
            region: default_tc_bench_region(),
            worker_bundle_sha256: None,
            wasm_bundle_sha256: None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct HooksConfig {
    #[serde(default = "default_hooks_max_ticket_ttl_seconds")]
    pub max_ticket_ttl_seconds: u64,
    #[serde(default = "default_hooks_max_scopes_per_ticket")]
    pub max_scopes_per_ticket: usize,
    #[serde(default = "default_hooks_max_active_sse_streams")]
    pub max_active_sse_streams: usize,
    #[serde(default = "default_hooks_sse_broadcast_capacity")]
    pub sse_broadcast_capacity: usize,
    #[serde(default = "default_hooks_max_webhook_subscriptions_per_space")]
    pub max_webhook_subscriptions_per_space: usize,
    #[serde(default = "default_hooks_webhook_timeout_seconds")]
    pub webhook_timeout_seconds: u64,
    #[serde(default = "default_hooks_webhook_max_attempts")]
    pub webhook_max_attempts: usize,
}

fn default_hooks_max_ticket_ttl_seconds() -> u64 {
    300
}

fn default_hooks_max_scopes_per_ticket() -> usize {
    32
}

fn default_hooks_max_active_sse_streams() -> usize {
    100
}

fn default_hooks_sse_broadcast_capacity() -> usize {
    1024
}

fn default_hooks_max_webhook_subscriptions_per_space() -> usize {
    5
}

fn default_hooks_webhook_timeout_seconds() -> u64 {
    10
}

fn default_hooks_webhook_max_attempts() -> usize {
    5
}

impl Default for HooksConfig {
    fn default() -> Self {
        Self {
            max_ticket_ttl_seconds: default_hooks_max_ticket_ttl_seconds(),
            max_scopes_per_ticket: default_hooks_max_scopes_per_ticket(),
            max_active_sse_streams: default_hooks_max_active_sse_streams(),
            sse_broadcast_capacity: default_hooks_sse_broadcast_capacity(),
            max_webhook_subscriptions_per_space: default_hooks_max_webhook_subscriptions_per_space(
            ),
            webhook_timeout_seconds: default_hooks_webhook_timeout_seconds(),
            webhook_max_attempts: default_hooks_webhook_max_attempts(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq, Default)]
#[serde(tag = "type")]
pub enum Keys {
    #[serde(rename = "static", alias = "Static")]
    Static(Static),
    #[cfg(feature = "dstack")]
    #[serde(rename = "dstack", alias = "Dstack")]
    Dstack,
    #[default]
    #[serde(rename = "auto", alias = "Auto")]
    Auto,
    #[serde(rename = "provider", alias = "Provider")]
    Provider,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct TeeConfig {
    #[serde(default = "default_tee_mode")]
    pub mode: TeeMode,
    #[serde(default)]
    pub attestation: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq, Default)]
pub enum TeeMode {
    #[default]
    Auto,
    Dstack,
    Off,
}

fn default_tee_mode() -> TeeMode {
    TeeMode::Auto
}

impl Default for TeeConfig {
    fn default() -> Self {
        Self {
            mode: TeeMode::Auto,
            attestation: false,
        }
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq, Default)]
pub struct Static {
    #[serde_as(as = "Option<Base64<UrlSafe, Unpadded>>")]
    secret: Option<Vec<u8>>,
}

#[derive(Debug, thiserror::Error)]
pub enum SecretInitError {
    #[error("Secret required to be at least 32 bytes, but was {0}")]
    NotEnoughEntropy(usize),
    #[error("Missing secret")]
    MissingSecret,
}

impl TryFrom<Static> for StaticSecret {
    type Error = SecretInitError;
    fn try_from(s: Static) -> Result<Self, Self::Error> {
        let secret = s.secret.ok_or(SecretInitError::MissingSecret)?;
        StaticSecret::new(secret).map_err(|v| SecretInitError::NotEnoughEntropy(v.len()))
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, Hash, PartialEq, Eq)]
pub struct Logging {
    pub format: LoggingFormat,
    pub tracing: Tracing,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, Hash, PartialEq, Eq)]
pub enum LoggingFormat {
    #[default]
    Text,
    Json,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct Tracing {
    pub traceheader: String,
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, Hash, PartialEq, Eq)]
pub struct SpacesConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowlist: Option<SpaceAllowListService>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct SqlStorageConfig {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default = "default_sql_memory_threshold")]
    pub memory_threshold: ByteUnit,
}

fn default_sql_memory_threshold() -> ByteUnit {
    ByteUnit::Mebibyte(10)
}

impl Default for SqlStorageConfig {
    fn default() -> Self {
        Self {
            path: None,
            memory_threshold: default_sql_memory_threshold(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct DuckDbStorageConfig {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default = "default_duckdb_memory_threshold")]
    pub memory_threshold: ByteUnit,
    #[serde(default = "default_duckdb_idle_timeout")]
    pub idle_timeout_secs: u64,
    #[serde(default = "default_duckdb_max_memory")]
    pub max_memory_per_connection: String,
}

fn default_duckdb_memory_threshold() -> ByteUnit {
    ByteUnit::Mebibyte(10)
}

fn default_duckdb_idle_timeout() -> u64 {
    300
}

fn default_duckdb_max_memory() -> String {
    "128MB".to_string()
}

impl Default for DuckDbStorageConfig {
    fn default() -> Self {
        Self {
            path: None,
            memory_threshold: default_duckdb_memory_threshold(),
            idle_timeout_secs: default_duckdb_idle_timeout(),
            max_memory_per_connection: default_duckdb_max_memory(),
        }
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct Storage {
    /// Root directory for all local data (database, blocks, sql, duckdb).
    /// Individual paths can still be overridden explicitly.
    #[serde(default = "default_datadir")]
    pub datadir: PathBuf,
    #[serde_as(as = "FromInto<BlockStorage>")]
    #[serde(default = "fs_store")]
    pub blocks: BlockConfig,
    #[serde_as(as = "FromInto<StagingStorage>")]
    #[serde(default = "memory_stage")]
    pub staging: BlockStage,
    #[serde(default)]
    pub database: Option<String>,
    pub limit: Option<ByteUnit>,
    #[serde(default)]
    pub sql: SqlStorageConfig,
    #[serde(default)]
    pub duckdb: DuckDbStorageConfig,
}

fn default_datadir() -> PathBuf {
    PathBuf::from("./data")
}

impl Storage {
    /// Resolve all unset paths relative to `datadir`.
    /// Call this after config extraction so that overrides from
    /// tinycloud.toml or TINYCLOUD_ env vars take precedence.
    pub fn resolve(&mut self) {
        let dir = &self.datadir;

        if self.database.is_none() {
            self.database = Some(format!("sqlite:{}", dir.join("caps.db").display()));
        }

        if self.sql.path.is_none() {
            self.sql.path = Some(dir.join("sql").to_string_lossy().into_owned());
        }

        if self.duckdb.path.is_none() {
            self.duckdb.path = Some(dir.join("duckdb").to_string_lossy().into_owned());
        }

        // Resolve blocks path if it's the Local variant with the empty default
        if let BlockConfig::B(ref fs) = self.blocks {
            if fs.path().as_os_str().is_empty() {
                self.blocks = BlockConfig::B(FileSystemConfig::new(dir.join("blocks")));
            }
        }

        if self.limit.map(|limit| limit.as_u64()) == Some(0) {
            self.limit = None;
        }
    }

    /// Get the database connection string. Panics if called before resolve().
    pub fn database(&self) -> &str {
        self.database
            .as_deref()
            .expect("Storage::resolve() must be called before accessing database")
    }
}

impl Default for Storage {
    fn default() -> Self {
        Self {
            datadir: default_datadir(),
            blocks: BlockStorage::default().into(),
            staging: StagingStorage::default().into(),
            database: None,
            limit: None,
            sql: SqlStorageConfig::default(),
            duckdb: DuckDbStorageConfig::default(),
        }
    }
}

fn memory_stage() -> BlockStage {
    StagingStorage::Memory.into()
}

fn fs_store() -> BlockConfig {
    BlockStorage::default().into()
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum BlockStorage {
    Local(FileSystemConfig),
    S3(S3BlockConfig),
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq, Default)]
pub enum StagingStorage {
    FileSystem,
    #[default]
    Memory,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct Relay {
    pub address: String,
    pub port: u16,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq, Default)]
pub struct Telemetry {
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct Prometheus {
    pub port: u16,
}

impl Default for Tracing {
    fn default() -> Tracing {
        Tracing {
            enabled: false,
            traceheader: "TinyCloud-Trace-Id".to_string(),
        }
    }
}

impl Default for BlockStorage {
    fn default() -> BlockStorage {
        BlockStorage::Local(FileSystemConfig::default())
    }
}

impl Default for Relay {
    fn default() -> Self {
        Self {
            address: "127.0.0.1".into(),
            port: 8081,
        }
    }
}

impl Default for Prometheus {
    fn default() -> Self {
        Self { port: 8001 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn enabled_config() -> ShareEmailConfig {
        ShareEmailConfig {
            enabled: true,
            target_origin: "https://node.internal.tinycloud".into(),
            node_audience: "did:web:node.internal.tinycloud".into(),
            node_signing_kid: "did:web:node.internal.tinycloud#invitation-key-1".into(),
            invitation_kid: "did:web:node.internal.tinycloud#invitation-key-1".into(),
            invitation_public_key: Some("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8".into()),
            issuer_did: "did:web:issuer.credentials.org".into(),
            issuer_kid: "did:web:issuer.credentials.org#email-signing-key-1".into(),
            issuer_public_key: Some("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA".into()),
            authority_material_path: Some("/run/tinycloud/authority-material.json".into()),
            ..ShareEmailConfig::default()
        }
    }

    fn install_bundle(config: &mut ShareEmailConfig) -> NamedTempFile {
        let file = NamedTempFile::new().expect("temporary trust bundle");
        let bundle = serde_json::json!({
            "version": "tinycloud.share-email-trust-bundle/v1",
            "shareOrigin": "https://share.tinycloud.xyz",
            "returnOrigin": config.return_origin.clone(),
            "registryOrigin": "https://registry.tinycloud.xyz",
            "credentialsOrigin": "https://witness.credentials.org",
            "nodeOrigin": config.target_origin.clone(),
            "nodeAudience": config.node_audience.clone(),
            "nodeInvitationKid": config.invitation_kid.clone(),
            "nodeInvitationPublicKey": config.invitation_public_key.clone(),
            "nodeKeyVersion": 1,
            "nodeEnabled": true,
            "issuerDid": config.issuer_did.clone(),
            "issuerVct": config.issuer_vct.clone(),
            "issuerKid": config.issuer_kid.clone(),
            "issuerPublicKey": config.issuer_public_key.clone(),
            "issuerKeyVersion": config.issuer_key_version,
            "issuerEnabled": true
        });
        file.as_file()
            .write_all(serde_json::to_string(&bundle).unwrap().as_bytes())
            .expect("trust bundle write");
        config.trust_bundle_path = Some(file.path().display().to_string());
        file
    }

    #[tokio::test]
    async fn enabled_share_email_requires_complete_trust_material() {
        let config = ShareEmailConfig {
            enabled: true,
            ..ShareEmailConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[cfg(not(feature = "mounted-fixture"))]
    #[tokio::test]
    async fn production_requires_the_authoritative_trust_bundle() {
        let config = enabled_config();
        assert_eq!(
            config.resolve_trust_bundle(),
            Err("share email trust bundle is required")
        );
    }

    #[cfg(not(feature = "mounted-fixture"))]
    #[tokio::test]
    async fn production_rejects_unreadable_and_malformed_trust_bundles() {
        let mut config = enabled_config();
        config.trust_bundle_path = Some("/tmp/tinycloud-share-email-missing-bundle".into());
        assert_eq!(
            config.resolve_trust_bundle(),
            Err("share email trust bundle is unreadable")
        );

        let mut config = enabled_config();
        let file = NamedTempFile::new().expect("temporary malformed bundle");
        file.as_file()
            .write_all(b"not-json")
            .expect("malformed bundle write");
        config.trust_bundle_path = Some(file.path().display().to_string());
        assert_eq!(
            config.resolve_trust_bundle(),
            Err("share email trust bundle is invalid")
        );
    }

    #[cfg(not(feature = "mounted-fixture"))]
    #[tokio::test]
    async fn production_rejects_trust_bundle_conflicts_and_fixture_identities() {
        let mut config = enabled_config();
        let _file = install_bundle(&mut config);
        config.target_origin = "https://different.internal.tinycloud".into();
        assert_eq!(
            config.resolve_trust_bundle(),
            Err("share email trust bundle disagrees with configured trust")
        );

        let mut config = enabled_config();
        let file = install_bundle(&mut config);
        let bundle = serde_json::json!({
            "version": "tinycloud.share-email-trust-bundle/v1",
            "shareOrigin": "https://share.tinycloud.xyz",
            "returnOrigin": "https://share.tinycloud.xyz",
            "registryOrigin": "https://registry.tinycloud.xyz",
            "credentialsOrigin": "https://witness.credentials.org",
            "nodeOrigin": "https://node.example",
            "nodeAudience": "did:web:node.example",
            "nodeInvitationKid": "did:web:node.example#invitation-key-1",
            "nodeInvitationPublicKey": config.invitation_public_key,
            "nodeKeyVersion": 1,
            "nodeEnabled": true,
            "issuerDid": "did:web:issuer.credentials.org",
            "issuerVct": "opencredentials.email/v1",
            "issuerKid": "did:web:issuer.credentials.org#email-signing-key-1",
            "issuerPublicKey": config.issuer_public_key,
            "issuerKeyVersion": 1,
            "issuerEnabled": true
        });
        fs::write(file.path(), serde_json::to_vec(&bundle).unwrap()).expect("fixture bundle write");
        config.target_origin.clear();
        config.node_audience.clear();
        config.node_signing_kid.clear();
        config.invitation_kid.clear();
        config.issuer_did.clear();
        config.issuer_kid.clear();
        assert_eq!(
            config.resolve_trust_bundle(),
            Err("share email trust bundle is inconsistent")
        );
    }

    #[tokio::test]
    async fn wildcard_or_extra_browser_origins_are_rejected() {
        let mut config = enabled_config();
        config.allowed_origins = vec!["*".into()];
        assert!(config.validate().is_err());

        config.allowed_origins = vec![config.return_origin.clone(), "https://evil.example".into()];
        assert!(config.validate().is_err());
    }

    #[tokio::test]
    async fn issuer_vct_is_pinned_to_the_frozen_opencredentials_profile() {
        let mut config = enabled_config();
        config.issuer_vct = "opencredentials.email/test".into();
        assert!(config.validate().is_err());
    }

    #[tokio::test]
    async fn production_rejects_placeholder_and_repeated_fixture_trust() {
        let mut config = enabled_config();
        config.target_origin = "https://node.example".into();
        if !allows_hermetic_fixture() {
            assert!(config.validate().is_err());
        }

        let mut config = enabled_config();
        config.invitation_public_key = Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into());
        if !allows_hermetic_fixture() {
            assert!(config.validate().is_err());
        }
    }

    #[tokio::test]
    async fn postgres_requires_verify_full_and_an_existing_ca_bundle() {
        let config = enabled_config();
        assert!(config
            .validate_for_database("postgres://user:password@db.example/share")
            .is_err());

        let mut config = enabled_config();
        config.postgres_tls.sslmode = "require".into();
        config.postgres_tls.root_cert_path = Some("/tmp/does-not-exist.pem".into());
        assert!(config
            .validate_for_database("postgres://user:password@db.example/share?sslmode=verify-full")
            .is_err());
    }

    #[tokio::test]
    async fn postgres_tls_validation_accepts_only_the_configured_ca_bundle() {
        let file = tempfile::NamedTempFile::new().expect("temporary CA bundle");
        let mut config = enabled_config();
        let _trust_bundle = install_bundle(&mut config);
        config.postgres_tls.sslmode = "verify-full".into();
        config.postgres_tls.root_cert_path = Some(file.path().display().to_string());

        assert!(config
            .validate_for_database(
                "postgresql://user:password@db.example/share?sslmode=verify-full"
            )
            .is_ok());
        assert!(config
            .validate_for_database(
                "postgresql://user:password@db.example/share?sslmode=verify-full&sslmode=require"
            )
            .is_err());
        assert!(config
            .validate_for_database(
                "postgresql://user:password@db.example/share?sslmode=verify-full&sslrootcert=/tmp/other.pem"
            )
            .is_err());
    }

    #[tokio::test]
    async fn sqlite_fixture_does_not_accept_postgres_tls_overrides() {
        let mut config = enabled_config();
        config.postgres_tls.sslmode = "verify-full".into();
        assert!(config
            .validate_for_database("sqlite:/tmp/tinycloud-share-email.db")
            .is_err());
    }
}
