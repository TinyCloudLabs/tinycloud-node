//! Exact-email N0a seam.
//!
//! This leaf declares no routes, storage schema, configuration, or authority
//! composition.  The integration owner wires it from `lib.rs` after N1/N2/N3
//! provide their implementations.

pub mod fakes;
pub mod ports;
pub mod types;

pub use ports::{
    CredentialVerifier, KvReadAdapter, NamedSqlReadAdapter, PolicyAuthorityBridge117,
    PolicyAuthorityTransaction117, PortError,
};
pub use types::{
    Action, AuthorizedRead, ContentSource, CredentialVerificationEvidence, DatabaseName, Did,
    DidKey, ExactResource, HolderEquation, KvGetAction, MarkdownDocument, NamedStatement, Origin,
    Path, PolicyCid, PolicySession, PolicySessionRequest, ProtocolJti, ProtocolNonce,
    ReadAuthorizationRequest, ReadInvocation, Resource, SafeJsonInteger, SessionHandle,
    Sha256Digest, ShareAction, ShareCid, ShareId, ShareScope, SqlReadAction, TargetOrigin,
    TypeError, KV_GET_ACTION, KV_POLICY_CID, KV_SHARE_CID, MARKDOWN_MEDIA_TYPE, MAX_CID_BYTES,
    MAX_DATABASE_NAME_BYTES, MAX_MARKDOWN_BYTES, MAX_SHARE_ID_BYTES, SQL_POLICY_CID,
    SQL_READ_ACTION, SQL_SHARE_CID,
};
