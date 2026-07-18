//! Node identity storage and backup helpers.
//!
//! The encrypted-file backend protects against casual copying and backup
//! leakage. It does not defend against a root attacker or a fully compromised
//! local machine.

use anyhow::{anyhow, bail, Context, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json as json;
use serde_with::{
    base64::{Base64, UrlSafe},
    formats::Unpadded,
    serde_as,
};
use std::{
    env, fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use tinycloud_core::keys::StaticSecret;

#[cfg(target_os = "macos")]
use core_foundation::{
    base::{CFType, TCFType},
    boolean::CFBoolean,
    data::{CFData, CFDataRef},
    dictionary::CFDictionary,
    string::CFString,
};
#[cfg(target_os = "macos")]
use core_foundation_sys::base::{CFGetTypeID, CFRelease, CFTypeRef};
#[cfg(target_os = "macos")]
use core_foundation_sys::string::CFStringRef;
#[cfg(target_os = "macos")]
use security_framework_sys::{
    access_control::kSecAttrAccessibleAfterFirstUnlock,
    base::{errSecDuplicateItem, errSecItemNotFound},
    item::{
        kSecAttrAccount, kSecAttrService, kSecAttrSynchronizable, kSecAttrSynchronizableAny,
        kSecClass, kSecClassGenericPassword, kSecReturnData, kSecUseAuthenticationUI,
        kSecUseAuthenticationUISkip, kSecUseDataProtectionKeychain, kSecValueData,
    },
    keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemDelete},
};
#[cfg(target_os = "macos")]
extern "C" {
    static kSecAttrAccessible: CFStringRef;
}
#[cfg(target_os = "macos")]
use sha2::{Digest, Sha256};
#[cfg(feature = "dstack")]
use std::future::Future;

use crate::{config::Keys, node_control::paths::KeyBackend};

#[cfg(target_os = "macos")]
use super::paths::SERVICE_LABEL;

const STATIC_ENV_KEY: &str = "TINYCLOUD_KEYS_SECRET";
#[cfg(target_os = "macos")]
const KEYCHAIN_SERVICE: &str = "xyz.tinycloud.node.identity";
#[cfg(target_os = "macos")]
const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34018;
#[cfg(target_os = "macos")]
const ERR_SEC_NOT_AVAILABLE: i32 = -25291;
#[cfg(target_os = "macos")]
const ERR_SEC_NO_DEFAULT_KEYCHAIN: i32 = -25307;
const ENCRYPTED_FILE_AAD: &[u8] = b"tinycloud-node/encrypted-file/v1";
const ENCRYPTED_FILE_KEY_WRAP_AAD: &[u8] = b"tinycloud-node/encrypted-file/key-wrap/v1";
const BACKUP_AAD: &[u8] = b"tinycloud-node/key-backup/v1";
const FILE_KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const KEK_SALT_LEN: usize = 16;
const FILE_VERSION: u8 = 1;
const BACKUP_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityPurpose {
    Serve,
    Probe,
    Backup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentitySourceKind {
    StaticEnv,
    StaticConfig,
    Dstack,
    Provider,
    Missing,
}

#[derive(Clone)]
pub struct IdentityState {
    pub source: IdentitySourceKind,
    pub backend: Option<KeyBackend>,
    pub secret: Option<StaticSecret>,
    pub node_did: Option<String>,
    pub identity_ready: bool,
    pub created: bool,
}

impl std::fmt::Debug for IdentityState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityState")
            .field("source", &self.source)
            .field("backend", &self.backend)
            .field(
                "secret",
                &self.secret.as_ref().map(|secret| secret.as_bytes().len()),
            )
            .field("node_did", &self.node_did)
            .field("identity_ready", &self.identity_ready)
            .field("created", &self.created)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentitySnapshot {
    pub contract_version: String,
    pub identity_ready: bool,
    pub key_backend: Option<KeyBackend>,
    pub node_did: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupResult {
    pub contract_version: String,
    pub backup_path: String,
    pub key_backend: KeyBackend,
    pub node_did: String,
}

pub trait KeyProvider: Send + Sync {
    fn backend(&self) -> KeyBackend;
    fn load_secret(&self) -> Result<Option<Vec<u8>>>;
    fn store_secret(&self, secret: &[u8]) -> Result<()>;
    fn delete_secret(&self) -> Result<()>;
}

pub fn default_provider_backend() -> KeyBackend {
    #[cfg(target_os = "macos")]
    {
        KeyBackend::MacosKeychain
    }

    #[cfg(not(target_os = "macos"))]
    {
        KeyBackend::EncryptedFile
    }
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MacosKeychainTier {
    DataProtection,
    Classic,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MacosStoreOutcome {
    Stored,
    Duplicate,
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
enum MacosLookupOutcome {
    Found(Vec<u8>),
    Missing,
    EntitlementMissing,
}

#[cfg(target_os = "macos")]
impl MacosKeychainTier {
    fn synchronizable(self) -> Option<CFType> {
        match self {
            MacosKeychainTier::DataProtection => Some(CFBoolean::true_value().into_CFType()),
            MacosKeychainTier::Classic => None,
        }
    }

    fn accessible(self) -> Option<CFType> {
        match self {
            MacosKeychainTier::DataProtection => Some(
                unsafe { CFString::wrap_under_get_rule(kSecAttrAccessibleAfterFirstUnlock) }
                    .into_CFType(),
            ),
            MacosKeychainTier::Classic => None,
        }
    }

    fn uses_data_protection_keychain(self) -> bool {
        matches!(self, MacosKeychainTier::DataProtection)
    }
}

pub fn default_backup_path(data_root: &Path) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default();
    data_root
        .join("backups")
        .join(format!("node-key-{stamp}.bundle"))
}

pub fn resolve_identity_state(
    keys: Option<&Keys>,
    data_root: &Path,
    purpose: IdentityPurpose,
) -> Result<IdentityState> {
    if let Some(secret) = resolve_static_env_secret()? {
        return Ok(static_state(IdentitySourceKind::StaticEnv, secret));
    }

    match keys {
        Some(Keys::Static(static_cfg)) => {
            let secret = StaticSecret::try_from(static_cfg.clone())
                .map_err(|err| anyhow!(err))
                .context("failed to load static identity secret from config")?;
            Ok(static_state(IdentitySourceKind::StaticConfig, secret))
        }
        None | Some(Keys::Auto) => resolve_auto_state(data_root, purpose),
        Some(Keys::Provider) => resolve_provider_state(data_root, purpose),
        #[cfg(feature = "dstack")]
        Some(Keys::Dstack) => resolve_dstack_state(purpose),
    }
}

pub fn backup_identity(
    keys: Option<&Keys>,
    data_root: &Path,
    passphrase: &[u8],
    output: Option<PathBuf>,
) -> Result<BackupResult> {
    let state = resolve_identity_state(keys, data_root, IdentityPurpose::Backup)?;
    let secret = state
        .secret
        .ok_or_else(|| anyhow!("node identity is not ready"))?;
    let node_did = state
        .node_did
        .ok_or_else(|| anyhow!("node identity is not ready"))?;
    let backend = state
        .backend
        .ok_or_else(|| anyhow!("node identity backend unavailable"))?;
    let output_path = output.unwrap_or_else(|| default_backup_path(data_root));
    let bundle = build_backup_bundle(&secret, backend, &node_did, passphrase)?;

    ensure_parent_dir(&output_path)?;
    write_private_json_file(&output_path, &bundle)?;

    Ok(BackupResult {
        contract_version: crate::node_control::paths::CONTROL_CONTRACT_VERSION.to_string(),
        backup_path: output_path.display().to_string(),
        key_backend: backend,
        node_did,
    })
}

pub fn identity_snapshot(state: &IdentityState) -> IdentitySnapshot {
    IdentitySnapshot {
        contract_version: crate::node_control::paths::CONTROL_CONTRACT_VERSION.to_string(),
        identity_ready: state.identity_ready,
        key_backend: state.backend,
        node_did: state.node_did.clone(),
    }
}

pub fn identity_did(secret: &StaticSecret) -> String {
    secret.node_did()
}

pub fn provider_for(data_root: &Path, backend: KeyBackend) -> Result<Box<dyn KeyProvider>> {
    match backend {
        KeyBackend::MacosKeychain => {
            #[cfg(target_os = "macos")]
            {
                Ok(Box::new(MacosKeychainProvider::new(data_root)))
            }

            #[cfg(not(target_os = "macos"))]
            {
                bail!("macOS keychain backend is unavailable on this platform")
            }
        }
        KeyBackend::EncryptedFile => Ok(Box::new(EncryptedFileProvider::new(data_root))),
        KeyBackend::Static => bail!("static secrets are not a provider backend"),
        KeyBackend::Dstack => bail!("dstack is not a provider backend"),
    }
}

fn resolve_static_env_secret() -> Result<Option<StaticSecret>> {
    match env::var(STATIC_ENV_KEY) {
        Ok(rendered) => {
            let decoded = base64::decode_config(rendered.trim(), base64::URL_SAFE_NO_PAD)
                .context("failed to decode TINYCLOUD_KEYS_SECRET as url-safe base64")?;
            Ok(Some(StaticSecret::new(decoded).map_err(|bytes| {
                anyhow!(
                    "static identity secret must be at least 32 bytes, got {}",
                    bytes.len()
                )
            })?))
        }
        Err(env::VarError::NotPresent) => Ok(None),
        Err(err) => Err(err).context("failed to read TINYCLOUD_KEYS_SECRET"),
    }
}

fn static_state(source: IdentitySourceKind, secret: StaticSecret) -> IdentityState {
    let node_did = secret.node_did();
    identity_state(source, Some(secret), Some(node_did), true, false)
}

fn resolve_auto_state(data_root: &Path, purpose: IdentityPurpose) -> Result<IdentityState> {
    #[cfg(feature = "dstack")]
    {
        match env::var("TINYCLOUD_TEE_MODE").ok().as_deref() {
            Some("dstack") => return resolve_dstack_state(purpose),
            Some("off") => return resolve_provider_state(data_root, purpose),
            _ => {
                if crate::dstack::is_available() {
                    ::tracing::info!("dstack socket detected, using TEE key derivation");
                    return resolve_dstack_state(purpose);
                }
            }
        }
    }

    resolve_provider_state(data_root, purpose)
}

#[cfg(feature = "dstack")]
fn resolve_dstack_state(purpose: IdentityPurpose) -> Result<IdentityState> {
    #[cfg(feature = "dstack")]
    {
        match block_on_async(crate::dstack::get_key("tinycloud/keys/primary")) {
            Ok(key_bytes) => {
                let secret = StaticSecret::new(key_bytes)
                    .map_err(|bytes| anyhow!("dstack key too short: {} bytes", bytes.len()))?;
                let node_did = secret.node_did();
                Ok(identity_state(
                    IdentitySourceKind::Dstack,
                    Some(secret),
                    Some(node_did),
                    true,
                    false,
                ))
            }
            Err(err) => match purpose {
                IdentityPurpose::Probe => Ok(identity_state(
                    IdentitySourceKind::Dstack,
                    None,
                    None,
                    false,
                    false,
                )),
                IdentityPurpose::Serve | IdentityPurpose::Backup => {
                    Err(err).context("failed to load dstack node identity key")
                }
            },
        }
    }

    #[cfg(not(feature = "dstack"))]
    {
        match purpose {
            IdentityPurpose::Probe => Ok(identity_state(
                IdentitySourceKind::Dstack,
                None,
                None,
                false,
                false,
            )),
            IdentityPurpose::Serve | IdentityPurpose::Backup => {
                bail!("dstack support is not enabled in this build")
            }
        }
    }
}

fn resolve_provider_state(data_root: &Path, purpose: IdentityPurpose) -> Result<IdentityState> {
    let backend = default_provider_backend();
    let provider = provider_for(data_root, backend)?;
    match provider.load_secret()? {
        Some(secret_bytes) => {
            let secret = StaticSecret::new(secret_bytes).map_err(|bytes| {
                anyhow!(
                    "stored identity secret must be at least 32 bytes, got {}",
                    bytes.len()
                )
            })?;
            let node_did = secret.node_did();
            Ok(identity_state(
                IdentitySourceKind::Provider,
                Some(secret),
                Some(node_did),
                true,
                false,
            ))
        }
        None => match purpose {
            IdentityPurpose::Serve => {
                let secret = generate_identity_secret();
                provider
                    .store_secret(&secret)
                    .context("failed to create first node identity secret")?;
                let secret = StaticSecret::new(secret.to_vec())
                    .expect("generated identity secret is always 32 bytes");
                let node_did = secret.node_did();
                tracing::info!(
                    backend = ?backend,
                    data_path = %data_root.display(),
                    "generated node identity secret on first run"
                );
                Ok(identity_state(
                    IdentitySourceKind::Provider,
                    Some(secret),
                    Some(node_did),
                    true,
                    true,
                ))
            }
            IdentityPurpose::Probe => Ok(identity_state(
                IdentitySourceKind::Provider,
                None,
                None,
                false,
                false,
            )),
            IdentityPurpose::Backup => bail!("node identity is not ready"),
        },
    }
}

#[cfg(feature = "dstack")]
fn block_on_async<F>(future: F) -> F::Output
where
    F: Future,
{
    if let Ok(handle) = rocket::tokio::runtime::Handle::try_current() {
        rocket::tokio::task::block_in_place(|| handle.block_on(future))
    } else {
        let runtime = rocket::tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("temporary tokio runtime should build");
        runtime.block_on(future)
    }
}

fn identity_state(
    source: IdentitySourceKind,
    secret: Option<StaticSecret>,
    node_did: Option<String>,
    identity_ready: bool,
    created: bool,
) -> IdentityState {
    IdentityState {
        source,
        backend: match source {
            IdentitySourceKind::StaticEnv | IdentitySourceKind::StaticConfig => {
                Some(KeyBackend::Static)
            }
            IdentitySourceKind::Dstack => Some(KeyBackend::Dstack),
            IdentitySourceKind::Provider => Some(default_provider_backend()),
            IdentitySourceKind::Missing => None,
        },
        secret,
        node_did,
        identity_ready,
        created,
    }
}

fn generate_identity_secret() -> [u8; FILE_KEY_LEN] {
    let mut secret = [0u8; FILE_KEY_LEN];
    OsRng.fill_bytes(&mut secret);
    secret
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    Ok(())
}

fn write_private_json_file<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let rendered = json::to_vec_pretty(value)?;
    fs::write(path, rendered).with_context(|| format!("failed to write {}", path.display()))?;
    set_private_permissions(path)?;
    Ok(())
}

fn write_private_bytes_file(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes).with_context(|| format!("failed to write {}", path.display()))?;
    set_private_permissions(path)?;
    Ok(())
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)
        .with_context(|| format!("failed to stat {}", path.display()))?
        .permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(path, permissions)
        .with_context(|| format!("failed to chmod {}", path.display()))
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

fn derive_scrypt_key(password: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
    // Keep local KDF costs practical while still using scrypt for KEK derivation.
    let params = scrypt::Params::new(15, 8, 1, 32).expect("valid scrypt params");
    let mut output = [0u8; 32];
    scrypt::scrypt(password, salt, &params, &mut output).context("scrypt key derivation failed")?;
    Ok(output)
}

fn nonce_bytes() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

fn salt_bytes() -> [u8; KEK_SALT_LEN] {
    let mut salt = [0u8; KEK_SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

fn encrypt_xchacha(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .context("xchacha20poly1305 key initialization failed")?;
    let cipher_nonce = XNonce::from(*nonce);
    cipher
        .encrypt(
            &cipher_nonce,
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .context("xchacha20poly1305 encryption failed")
}

fn decrypt_xchacha(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .context("xchacha20poly1305 key initialization failed")?;
    let cipher_nonce = XNonce::from(*nonce);
    cipher
        .decrypt(
            &cipher_nonce,
            chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
        .context("xchacha20poly1305 decryption failed")
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BackupBundleV1 {
    version: u8,
    backend: KeyBackend,
    node_did: String,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    kdf_salt: Vec<u8>,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    nonce: Vec<u8>,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    ciphertext: Vec<u8>,
}

fn build_backup_bundle(
    secret: &StaticSecret,
    backend: KeyBackend,
    node_did: &str,
    passphrase: &[u8],
) -> Result<BackupBundleV1> {
    if passphrase.is_empty() {
        bail!("passphrase is required")
    }
    let kdf_salt = salt_bytes();
    let outer_key = derive_scrypt_key(passphrase, &kdf_salt)?;
    let nonce = nonce_bytes();
    let ciphertext = encrypt_xchacha(&outer_key, &nonce, BACKUP_AAD, secret.as_bytes())?;

    Ok(BackupBundleV1 {
        version: BACKUP_VERSION,
        backend,
        node_did: node_did.to_string(),
        kdf_salt: kdf_salt.to_vec(),
        nonce: nonce.to_vec(),
        ciphertext,
    })
}

fn decode_backup_bundle(bundle: &BackupBundleV1, passphrase: &[u8]) -> Result<Vec<u8>> {
    if bundle.version != BACKUP_VERSION {
        bail!("unsupported backup bundle version {}", bundle.version)
    }
    let outer_key = derive_scrypt_key(passphrase, &bundle.kdf_salt)?;
    let nonce: [u8; NONCE_LEN] = bundle
        .nonce
        .as_slice()
        .try_into()
        .context("invalid backup nonce length")?;
    decrypt_xchacha(&outer_key, &nonce, BACKUP_AAD, &bundle.ciphertext)
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncryptedIdentityFileV1 {
    version: u8,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    kek_salt: Vec<u8>,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    wrapped_file_key_nonce: Vec<u8>,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    wrapped_file_key_ciphertext: Vec<u8>,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    payload_nonce: Vec<u8>,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    payload_ciphertext: Vec<u8>,
}

pub struct EncryptedFileProvider {
    keys_dir: PathBuf,
    identity_path: PathBuf,
    kek_secret_path: PathBuf,
}

impl EncryptedFileProvider {
    pub fn new(data_root: &Path) -> Self {
        let keys_dir = data_root.join("keys");
        Self {
            identity_path: keys_dir.join("identity.key.enc"),
            kek_secret_path: keys_dir.join("kek.secret"),
            keys_dir,
        }
    }

    fn ensure_kek_secret(&self) -> Result<Vec<u8>> {
        match fs::read(&self.kek_secret_path) {
            Ok(bytes) => Ok(bytes),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                ensure_parent_dir(&self.kek_secret_path)?;
                fs::create_dir_all(&self.keys_dir)
                    .with_context(|| format!("failed to create {}", self.keys_dir.display()))?;
                let secret = generate_identity_secret();
                write_private_bytes_file(&self.kek_secret_path, &secret)?;
                Ok(secret.to_vec())
            }
            Err(err) => Err(err)
                .with_context(|| format!("failed to read {}", self.kek_secret_path.display())),
        }
    }

    fn load_kek_secret(&self) -> Result<Option<Vec<u8>>> {
        match fs::read(&self.kek_secret_path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err)
                .with_context(|| format!("failed to read {}", self.kek_secret_path.display())),
        }
    }
}

impl KeyProvider for EncryptedFileProvider {
    fn backend(&self) -> KeyBackend {
        KeyBackend::EncryptedFile
    }

    fn load_secret(&self) -> Result<Option<Vec<u8>>> {
        if !self.identity_path.exists() {
            return Ok(None);
        }
        let rendered = fs::read(&self.identity_path)
            .with_context(|| format!("failed to read {}", self.identity_path.display()))?;
        let blob: EncryptedIdentityFileV1 = json::from_slice(&rendered)
            .with_context(|| format!("failed to parse {}", self.identity_path.display()))?;
        if blob.version != FILE_VERSION {
            bail!(
                "unsupported encrypted identity file version {}",
                blob.version
            );
        }
        let kek_secret = self
            .load_kek_secret()?
            .ok_or_else(|| anyhow!("missing KEK secret at {}", self.kek_secret_path.display()))?;
        let kek = derive_scrypt_key(&kek_secret, &blob.kek_salt)?;
        let wrapped_nonce: [u8; NONCE_LEN] = blob
            .wrapped_file_key_nonce
            .as_slice()
            .try_into()
            .context("invalid wrapped file key nonce length")?;
        let wrapped_file_key = decrypt_xchacha(
            &kek,
            &wrapped_nonce,
            ENCRYPTED_FILE_KEY_WRAP_AAD,
            &blob.wrapped_file_key_ciphertext,
        )?;
        if wrapped_file_key.len() != FILE_KEY_LEN {
            bail!(
                "wrapped file key must be 32 bytes, got {}",
                wrapped_file_key.len()
            );
        }
        let file_key: [u8; FILE_KEY_LEN] = wrapped_file_key
            .as_slice()
            .try_into()
            .context("wrapped file key length mismatch")?;
        let payload_nonce: [u8; NONCE_LEN] = blob
            .payload_nonce
            .as_slice()
            .try_into()
            .context("invalid payload nonce length")?;
        let secret = decrypt_xchacha(
            &file_key,
            &payload_nonce,
            ENCRYPTED_FILE_AAD,
            &blob.payload_ciphertext,
        )?;
        if secret.len() < 32 {
            bail!(
                "stored identity secret must be at least 32 bytes, got {}",
                secret.len()
            );
        }
        Ok(Some(secret))
    }

    fn store_secret(&self, secret: &[u8]) -> Result<()> {
        if secret.len() < 32 {
            bail!(
                "stored identity secret must be at least 32 bytes, got {}",
                secret.len()
            );
        }
        ensure_parent_dir(&self.identity_path)?;
        fs::create_dir_all(&self.keys_dir)
            .with_context(|| format!("failed to create {}", self.keys_dir.display()))?;
        let kek_secret = self.ensure_kek_secret()?;
        let kek_salt = salt_bytes();
        let kek = derive_scrypt_key(&kek_secret, &kek_salt)?;
        let file_key = generate_identity_secret();
        let wrapped_file_key_nonce = nonce_bytes();
        let payload_nonce = nonce_bytes();
        let wrapped_file_key_ciphertext = encrypt_xchacha(
            &kek,
            &wrapped_file_key_nonce,
            ENCRYPTED_FILE_KEY_WRAP_AAD,
            &file_key,
        )?;
        let payload_ciphertext =
            encrypt_xchacha(&file_key, &payload_nonce, ENCRYPTED_FILE_AAD, secret)?;
        let blob = EncryptedIdentityFileV1 {
            version: FILE_VERSION,
            kek_salt: kek_salt.to_vec(),
            wrapped_file_key_nonce: wrapped_file_key_nonce.to_vec(),
            wrapped_file_key_ciphertext,
            payload_nonce: payload_nonce.to_vec(),
            payload_ciphertext,
        };
        write_private_json_file(&self.identity_path, &blob)
    }

    fn delete_secret(&self) -> Result<()> {
        match fs::remove_file(&self.identity_path) {
            Ok(()) => (),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("failed to remove {}", self.identity_path.display()))
            }
        }
        match fs::remove_file(&self.kek_secret_path) {
            Ok(()) => (),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("failed to remove {}", self.kek_secret_path.display())
                })
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
pub struct MacosKeychainProvider {
    service: String,
    account: String,
}

#[cfg(target_os = "macos")]
impl MacosKeychainProvider {
    pub fn new(data_root: &Path) -> Self {
        Self {
            service: KEYCHAIN_SERVICE.to_string(),
            account: keychain_account(data_root),
        }
    }
}

#[cfg(target_os = "macos")]
impl KeyProvider for MacosKeychainProvider {
    fn backend(&self) -> KeyBackend {
        KeyBackend::MacosKeychain
    }

    fn load_secret(&self) -> Result<Option<Vec<u8>>> {
        match self.load_secret_in_tier(MacosKeychainTier::DataProtection)? {
            MacosLookupOutcome::Found(secret) => return validate_loaded_secret(secret),
            MacosLookupOutcome::Missing | MacosLookupOutcome::EntitlementMissing => {}
        }

        match self.load_secret_in_tier(MacosKeychainTier::Classic)? {
            MacosLookupOutcome::Found(secret) => validate_loaded_secret(secret),
            MacosLookupOutcome::Missing => Ok(None),
            MacosLookupOutcome::EntitlementMissing => Err(anyhow!(
                "keychain lookup failed with status {}",
                ERR_SEC_MISSING_ENTITLEMENT
            )),
        }
    }

    fn store_secret(&self, secret: &[u8]) -> Result<()> {
        if secret.len() < 32 {
            bail!(
                "stored identity secret must be at least 32 bytes, got {}",
                secret.len()
            );
        }

        match self.try_store_secret_in_tier(secret, MacosKeychainTier::DataProtection) {
            Ok(MacosStoreOutcome::Stored) => Ok(()),
            Ok(MacosStoreOutcome::Duplicate) => {
                self.replace_secret_in_tier(secret, MacosKeychainTier::DataProtection)
            }
            Err(status) if status == ERR_SEC_MISSING_ENTITLEMENT => {
                let warning = "macOS data-protection keychain insert lacks entitlement; falling back to the classic login keychain for this unentitled binary. iCloud Keychain sync will apply automatically in the signed desktop app.";
                eprintln!("warning: {warning}");
                match self.try_store_secret_in_tier(secret, MacosKeychainTier::Classic) {
                    Ok(MacosStoreOutcome::Stored) => Ok(()),
                    Ok(MacosStoreOutcome::Duplicate) => {
                        self.replace_secret_in_tier(secret, MacosKeychainTier::Classic)
                    }
                    Err(status) => Err(anyhow!("keychain insert failed with status {}", status)),
                }
            }
            Err(status) => Err(anyhow!("keychain insert failed with status {}", status)),
        }
    }

    fn delete_secret(&self) -> Result<()> {
        self.delete_secret_in_tier(MacosKeychainTier::DataProtection)?;
        self.delete_secret_in_tier(MacosKeychainTier::Classic)?;
        Ok(())
    }
}

#[cfg(target_os = "macos")]
impl MacosKeychainProvider {
    fn load_secret_in_tier(&self, tier: MacosKeychainTier) -> Result<MacosLookupOutcome> {
        let query = macos_lookup_query(&self.service, &self.account, tier);
        let mut result: CFTypeRef = std::ptr::null_mut();
        let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };
        match status {
            0 => Ok(MacosLookupOutcome::Found(macos_copy_result_bytes(result)?)),
            s if s == errSecItemNotFound => Ok(MacosLookupOutcome::Missing),
            s if s == ERR_SEC_MISSING_ENTITLEMENT => Ok(MacosLookupOutcome::EntitlementMissing),
            s => Err(anyhow!("keychain lookup failed with status {}", s)),
        }
    }

    fn try_store_secret_in_tier(
        &self,
        secret: &[u8],
        tier: MacosKeychainTier,
    ) -> Result<MacosStoreOutcome, i32> {
        let add_query = macos_add_query(&self.service, &self.account, secret, tier);
        let status = unsafe { SecItemAdd(add_query.as_concrete_TypeRef(), std::ptr::null_mut()) };
        match status {
            0 => Ok(MacosStoreOutcome::Stored),
            s if s == errSecDuplicateItem => Ok(MacosStoreOutcome::Duplicate),
            s => Err(s),
        }
    }

    fn replace_secret_in_tier(&self, secret: &[u8], tier: MacosKeychainTier) -> Result<()> {
        self.delete_secret_in_tier(tier)?;
        match self.try_store_secret_in_tier(secret, tier) {
            Ok(MacosStoreOutcome::Stored) => Ok(()),
            Ok(MacosStoreOutcome::Duplicate) => Err(anyhow!(
                "keychain update failed with status {}",
                errSecDuplicateItem
            )),
            Err(status) => Err(anyhow!("keychain insert failed with status {}", status)),
        }
    }

    fn delete_secret_in_tier(&self, tier: MacosKeychainTier) -> Result<()> {
        let query = macos_delete_query(&self.service, &self.account, tier);
        let status = unsafe { SecItemDelete(query.as_concrete_TypeRef()) };
        match status {
            0 => Ok(()),
            s if s == errSecItemNotFound => Ok(()),
            s if s == ERR_SEC_MISSING_ENTITLEMENT => Ok(()),
            s if s == ERR_SEC_NOT_AVAILABLE || s == ERR_SEC_NO_DEFAULT_KEYCHAIN => Ok(()),
            _ => Err(anyhow!("keychain delete failed with status {}", status)),
        }
    }
}

#[cfg(target_os = "macos")]
fn macos_common_pairs(service: &str, account: &str) -> Vec<(CFString, CFType)> {
    vec![
        (
            unsafe { CFString::wrap_under_get_rule(kSecClass) },
            unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword).into_CFType() },
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrService) },
            CFString::from(service).into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) },
            CFString::from(account).into_CFType(),
        ),
    ]
}

#[cfg(target_os = "macos")]
fn macos_lookup_query(
    service: &str,
    account: &str,
    tier: MacosKeychainTier,
) -> CFDictionary<CFString, CFType> {
    let mut pairs = macos_common_pairs(service, account);
    pairs.push((
        unsafe { CFString::wrap_under_get_rule(kSecUseAuthenticationUI) },
        unsafe { CFString::wrap_under_get_rule(kSecUseAuthenticationUISkip).into_CFType() },
    ));
    pairs.push((
        unsafe { CFString::wrap_under_get_rule(kSecAttrSynchronizable) },
        unsafe { CFString::wrap_under_get_rule(kSecAttrSynchronizableAny).into_CFType() },
    ));
    pairs.push((
        unsafe { CFString::wrap_under_get_rule(kSecReturnData) },
        CFBoolean::true_value().into_CFType(),
    ));
    if tier.uses_data_protection_keychain() {
        pairs.push((
            unsafe { CFString::wrap_under_get_rule(kSecUseDataProtectionKeychain) },
            CFBoolean::true_value().into_CFType(),
        ));
    }
    CFDictionary::from_CFType_pairs(&pairs)
}

#[cfg(target_os = "macos")]
fn macos_delete_query(
    service: &str,
    account: &str,
    tier: MacosKeychainTier,
) -> CFDictionary<CFString, CFType> {
    let mut pairs = macos_common_pairs(service, account);
    if let Some(synchronizable) = tier.synchronizable() {
        pairs.push((
            unsafe { CFString::wrap_under_get_rule(kSecAttrSynchronizable) },
            synchronizable,
        ));
    }
    if tier.uses_data_protection_keychain() {
        pairs.push((
            unsafe { CFString::wrap_under_get_rule(kSecUseDataProtectionKeychain) },
            CFBoolean::true_value().into_CFType(),
        ));
    }
    CFDictionary::from_CFType_pairs(&pairs)
}

#[cfg(target_os = "macos")]
fn macos_add_query(
    service: &str,
    account: &str,
    secret: &[u8],
    tier: MacosKeychainTier,
) -> CFDictionary<CFString, CFType> {
    let mut pairs = macos_common_pairs(service, account);
    if let Some(synchronizable) = tier.synchronizable() {
        pairs.push((
            unsafe { CFString::wrap_under_get_rule(kSecAttrSynchronizable) },
            synchronizable,
        ));
    }
    if let Some(accessible) = tier.accessible() {
        pairs.push((
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccessible) },
            accessible,
        ));
    }
    if tier.uses_data_protection_keychain() {
        pairs.push((
            unsafe { CFString::wrap_under_get_rule(kSecUseDataProtectionKeychain) },
            CFBoolean::true_value().into_CFType(),
        ));
    }
    pairs.push((
        unsafe { CFString::wrap_under_get_rule(kSecValueData) },
        CFData::from_buffer(secret).into_CFType(),
    ));

    CFDictionary::from_CFType_pairs(&pairs)
}

#[cfg(target_os = "macos")]
fn macos_copy_result_bytes(result: CFTypeRef) -> Result<Vec<u8>> {
    if result.is_null() {
        bail!("macOS keychain lookup returned no data");
    }

    let type_id = unsafe { CFGetTypeID(result) };
    if type_id != CFData::type_id() {
        unsafe {
            CFRelease(result);
        }
        bail!("macOS keychain lookup returned unexpected data");
    }

    let data = unsafe { CFData::wrap_under_create_rule(result as CFDataRef) };
    Ok(data.bytes().to_vec())
}

#[cfg(target_os = "macos")]
fn validate_loaded_secret(secret: Vec<u8>) -> Result<Option<Vec<u8>>> {
    if secret.len() < 32 {
        bail!(
            "stored identity secret must be at least 32 bytes, got {}",
            secret.len()
        );
    }

    Ok(Some(secret))
}

#[cfg(target_os = "macos")]
fn keychain_account(data_root: &Path) -> String {
    let digest = Sha256::digest(data_root.display().to_string().as_bytes());
    format!("{SERVICE_LABEL}.identity.{}", hex::encode(digest))
}

pub fn read_backup_bundle(path: &Path, passphrase: &[u8]) -> Result<Vec<u8>> {
    let rendered = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let bundle: BackupBundleV1 = json::from_slice(&rendered)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    let secret = decode_backup_bundle(&bundle, passphrase)?;
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[derive(Default)]
    struct EnvGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = env::var(key).ok();
            env::set_var(key, value);
            Self { key, previous }
        }

        fn unset(key: &'static str) -> Self {
            let previous = env::var(key).ok();
            env::remove_var(key);
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => env::set_var(self.key, value),
                None => env::remove_var(self.key),
            }
        }
    }

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::test_support::env_lock()
    }

    // Matches macOS Security framework "no keychain available" status codes.
    // Defined unconditionally so runtime `cfg!(target_os = "macos")` call sites
    // compile on all platforms.
    fn is_no_keychain_error(rendered: &str) -> bool {
        rendered.contains("-25291") || rendered.contains("-25307")
    }

    fn encode_env_secret(secret: &[u8]) -> String {
        base64::encode_config(secret, base64::URL_SAFE_NO_PAD)
    }

    #[test]
    fn encrypted_file_roundtrip_and_wrong_kek_fails() {
        let temp = tempdir().unwrap();
        let provider = EncryptedFileProvider::new(temp.path());
        let secret = [7u8; FILE_KEY_LEN];

        provider.store_secret(&secret).unwrap();
        let reloaded = provider.load_secret().unwrap().unwrap();
        assert_eq!(reloaded, secret);

        fs::write(provider.kek_secret_path.clone(), [9u8; KEK_SALT_LEN]).unwrap();
        let err = provider.load_secret().unwrap_err();
        let rendered = format!("{err:#}");
        assert!(rendered.contains("decrypt") || rendered.contains("failed"));
    }

    #[test]
    fn provider_selection_prefers_static_env() {
        let _lock = env_lock();
        let temp = tempdir().unwrap();
        let _env = EnvGuard::set(STATIC_ENV_KEY, &encode_env_secret(&[1u8; 32]));
        let state =
            resolve_identity_state(Some(&Keys::Provider), temp.path(), IdentityPurpose::Probe)
                .unwrap();
        assert_eq!(state.source, IdentitySourceKind::StaticEnv);
        assert_eq!(state.backend, Some(KeyBackend::Static));
        assert!(state.identity_ready);
        assert!(state.node_did.is_some());
    }

    #[test]
    fn provider_selection_prefers_static_config() {
        let _lock = env_lock();
        let temp = tempdir().unwrap();
        let _env = EnvGuard::unset(STATIC_ENV_KEY);
        let static_cfg: crate::config::Static = json::from_value(serde_json::json!({
            "secret": encode_env_secret(&[2u8; 32]),
        }))
        .unwrap();
        let state = resolve_identity_state(
            Some(&Keys::Static(static_cfg)),
            temp.path(),
            IdentityPurpose::Probe,
        )
        .unwrap();
        assert_eq!(state.source, IdentitySourceKind::StaticConfig);
        assert_eq!(state.backend, Some(KeyBackend::Static));
        assert!(state.identity_ready);
        assert!(state.node_did.is_some());
    }

    #[test]
    fn first_run_generation_uses_auto_provider_backend() {
        let _lock = env_lock();
        let temp = tempdir().unwrap();
        let _env = EnvGuard::unset(STATIC_ENV_KEY);
        let _tee_mode = EnvGuard::set("TINYCLOUD_TEE_MODE", "off");
        #[cfg(target_os = "macos")]
        let provider = MacosKeychainProvider::new(temp.path());
        #[cfg(target_os = "macos")]
        let _cleanup = KeychainCleanup(&provider);
        let state = match resolve_identity_state(None, temp.path(), IdentityPurpose::Serve) {
            Ok(state) => state,
            Err(err) => {
                let rendered = format!("{err:#}");
                if cfg!(target_os = "macos") && is_no_keychain_error(&rendered) {
                    return;
                }
                panic!("auto first run failed: {rendered}");
            }
        };

        assert_eq!(state.source, IdentitySourceKind::Provider);
        assert_eq!(state.backend, Some(default_provider_backend()));
        assert!(state.identity_ready);
        assert!(state.secret.is_some());
        assert!(state.node_did.is_some());
    }

    #[test]
    fn backup_bundle_seals_and_verifies() {
        let secret = StaticSecret::new(vec![3u8; FILE_KEY_LEN]).unwrap();
        let bundle = build_backup_bundle(
            &secret,
            KeyBackend::EncryptedFile,
            &secret.node_did(),
            b"correct horse battery staple",
        )
        .unwrap();

        let recovered = decode_backup_bundle(&bundle, b"correct horse battery staple").unwrap();
        assert_eq!(recovered, secret.as_bytes().to_vec());

        let err = decode_backup_bundle(&bundle, b"wrong passphrase").unwrap_err();
        let rendered = format!("{err:#}");
        assert!(rendered.contains("failed") || rendered.contains("decrypt"));
    }

    #[test]
    fn encrypted_file_provider_is_gated_by_provider_config() {
        let _lock = env_lock();
        let temp = tempdir().unwrap();
        let _env = EnvGuard::unset(STATIC_ENV_KEY);
        let state = match resolve_identity_state(
            Some(&Keys::Provider),
            temp.path(),
            IdentityPurpose::Serve,
        ) {
            Ok(state) => state,
            Err(err) => {
                let rendered = format!("{err:#}");
                if cfg!(target_os = "macos") && is_no_keychain_error(&rendered) {
                    return;
                }
                panic!("provider-backed first run failed: {rendered}");
            }
        };

        assert_eq!(state.source, IdentitySourceKind::Provider);
        assert_eq!(state.backend, Some(default_provider_backend()));
        assert!(state.identity_ready);
        assert!(state.secret.is_some());
        assert!(state.node_did.is_some());

        #[cfg(not(target_os = "macos"))]
        {
            assert!(state.created);
            assert!(temp.path().join("keys").join("identity.key.enc").exists());
            assert!(temp.path().join("keys").join("kek.secret").exists());
        }

        #[cfg(target_os = "macos")]
        {
            if let Ok(provider) = provider_for(temp.path(), default_provider_backend()) {
                let _ = provider.delete_secret();
            }
        }
    }

    #[cfg(target_os = "macos")]
    struct KeychainCleanup<'a>(&'a MacosKeychainProvider);

    #[cfg(target_os = "macos")]
    impl Drop for KeychainCleanup<'_> {
        fn drop(&mut self) {
            let _ = self.0.delete_secret();
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn keychain_roundtrip_uses_namespaced_item_and_deletes_it() {
        let temp = tempdir().unwrap();
        let random = rand::random::<u64>();
        let provider = MacosKeychainProvider {
            service: format!("xyz.tinycloud.node.test-{random}"),
            account: keychain_account(temp.path()),
        };
        let secret = [9u8; FILE_KEY_LEN];
        let _cleanup = KeychainCleanup(&provider);

        let _ = provider.delete_secret();
        match provider.store_secret(&secret) {
            Ok(()) => {}
            Err(err) => {
                let rendered = format!("{err:#}");
                if is_no_keychain_error(&rendered) {
                    return;
                }
                panic!("keychain roundtrip failed: {rendered}");
            }
        }

        let loaded = provider.load_secret().unwrap().unwrap();
        assert_eq!(loaded, secret);

        provider.delete_secret().unwrap();
        assert!(provider.load_secret().unwrap().is_none());
    }
}
