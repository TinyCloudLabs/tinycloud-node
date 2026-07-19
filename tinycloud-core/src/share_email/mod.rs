//! Exact-email protocol module.
//!
//! `bridge` is the N4 integration owner's sole concrete implementation of
//! [`ports::PolicyAuthorityTransaction117`]; every other leaf here is owned
//! by its originating lane (N1 `invitation`/`state`, N2 `verifier`, N3
//! `data_plane`). This module still declares no HTTP routes, configuration,
//! or app-state composition; that remains `lib.rs`'s responsibility.

pub mod bridge;
pub mod data_plane;
pub mod fakes;
pub mod invitation;
pub mod ports;
pub mod state;
pub mod types;
pub mod verifier;

pub use bridge::DatabaseAuthorityBridge117;
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
