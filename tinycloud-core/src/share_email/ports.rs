//! Minimal async ports for N2 verification, #117 authority (including N1
//! replay effects), and N3 Markdown reads. This module declares boundaries
//! only.

use async_trait::async_trait;
use time::OffsetDateTime;

use super::types::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PortError {
    #[error("share-email capability unavailable")]
    Unavailable,
    #[error("share-email request denied")]
    Denied,
    #[error("share-email replay")]
    Replay,
    #[error("share-email storage failure")]
    Storage,
}

/// N2 verifies the OpenCredentials credential and returns checked evidence.
#[async_trait]
pub trait CredentialVerifier: Send + Sync {
    async fn verify_credential(
        &self,
        credential: &[u8],
        expected_scope: &ShareScope,
        expected_holder: &DidKey,
    ) -> Result<CredentialVerificationEvidence, PortError>;
}

/// The only bridge from exact-email code into the refreshed #117 authority
/// kernel. A session handle or read invocation is not authority by itself.
/// Each method is an independent transaction and must commit all of its
/// authority, session, and replay effects together, or commit none of them.
#[async_trait]
pub trait PolicyAuthorityTransaction117: Send + Sync {
    /// Revalidate the policy authority, consume the policy nonce and
    /// presentation JTI, and persist the #117 session atomically.
    async fn establish_session(
        &self,
        request: PolicySessionRequest,
        now: OffsetDateTime,
    ) -> Result<PolicySession, PortError>;

    /// Revalidate the session and its complete #117 ancestry/revocation
    /// state, consume the read JTI, and authorize the exact request atomically.
    async fn authorize_read(
        &self,
        request: ReadAuthorizationRequest,
        now: OffsetDateTime,
    ) -> Result<AuthorizedRead, PortError>;
}

pub use PolicyAuthorityTransaction117 as PolicyAuthorityBridge117;

/// N3 reads only the grant emitted by #117 for an exact KV source.
#[async_trait]
pub trait KvReadAdapter: Send + Sync {
    async fn read_markdown(
        &self,
        authorized: AuthorizedRead,
    ) -> Result<MarkdownDocument, PortError>;
}

/// N3 executes only the named statement already constrained by #117.
#[async_trait]
pub trait NamedSqlReadAdapter: Send + Sync {
    async fn read_markdown(
        &self,
        authorized: AuthorizedRead,
    ) -> Result<MarkdownDocument, PortError>;
}
