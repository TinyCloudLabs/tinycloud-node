//! Public, read-only publication of the node's derived public key material.
//!
//! TC-359. The Share invitation signing key is derived *inside* the node from
//! whatever `StaticSecret` the boot resolved — in production that is the
//! dstack KMS (`TINYCLOUD_KEYS_TYPE=Dstack`), which never leaves the CVM. An
//! operator therefore had no way to learn the value that
//! `shareEmail.invitationPublicKey` has to be pinned to: the only exporter,
//! `export-share-invitation-descriptor`, requires a *static*
//! `TINYCLOUD_KEYS_SECRET` and so emits a key the running node never signs
//! with. The published production config ended up carrying a development
//! fixture key as a result.
//!
//! This record closes that gap. It is derived from the same `StaticSecret`
//! every other subsystem uses, so it is correct under every `Keys` backend
//! including `Keys::Dstack`; it contains public halves only; and it is served
//! unauthenticated because every value in it is meant to be published. It is
//! deliberately independent of the share-email runtime so the key can be read
//! *before* `shareEmail.enabled` is ever turned on.

use base64::{encode_config, URL_SAFE_NO_PAD};
use rocket::{serde::json::Json, State};
use serde::{Deserialize, Serialize};
use tinycloud_core::keys::StaticSecret;

/// The node's published public key material. Public halves only — nothing in
/// this struct can be used to sign.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NodePublicKeys {
    /// The node's stable identity DID (`did:key`), also used as the share-v2
    /// enforcer DID and the encryption-module audience.
    pub node_did: String,
    /// Unpadded base64url of the 32-byte ed25519 public half of the Share
    /// invitation signing key. This is exactly the value that
    /// `shareEmail.invitationPublicKey` (and the trust bundle's
    /// `nodeInvitationPublicKey`) must carry for this node.
    pub share_invitation_public_key: String,
}

impl NodePublicKeys {
    pub fn derive(secret: &StaticSecret) -> Self {
        Self {
            node_did: secret.node_did(),
            share_invitation_public_key: encode_config(
                secret.share_invitation_public_key(),
                URL_SAFE_NO_PAD,
            ),
        }
    }
}

/// `GET /.well-known/tinycloud/node-keys`
///
/// Read-only, unauthenticated, side-effect free: safe to call in production.
#[get("/.well-known/tinycloud/node-keys")]
pub fn node_keys(keys: &State<NodePublicKeys>) -> Json<NodePublicKeys> {
    Json(keys.inner().clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocket::local::asynchronous::Client;

    fn secret() -> StaticSecret {
        // A secret that is *not* reachable from the environment, standing in
        // for KMS-derived bytes.
        StaticSecret::new(
            (0u8..32)
                .map(|b| b.wrapping_mul(7).wrapping_add(3))
                .collect(),
        )
        .expect("32-byte test secret")
    }

    #[test]
    fn the_published_key_is_the_derived_share_invitation_public_key() {
        let secret = secret();
        let published = NodePublicKeys::derive(&secret);

        assert_eq!(
            published.share_invitation_public_key,
            encode_config(secret.share_invitation_public_key(), URL_SAFE_NO_PAD),
            "the published key must be the key the node actually signs invitations with"
        );
        assert_eq!(
            published.share_invitation_public_key.len(),
            43,
            "32 raw bytes render as 43 unpadded base64url characters"
        );
        assert_eq!(published.node_did, secret.node_did());
    }

    #[test]
    fn the_published_record_carries_no_secret_material() {
        let secret = secret();
        let rendered = serde_json::to_value(NodePublicKeys::derive(&secret)).expect("serialize");

        assert_eq!(
            rendered.as_object().expect("object").len(),
            2,
            "only nodeDid and shareInvitationPublicKey may be published"
        );
        let body = rendered.to_string();
        assert!(!body.contains(&encode_config(secret.as_bytes(), URL_SAFE_NO_PAD)));
        assert!(!body.contains(&hex::encode(secret.as_bytes())));
        // The private half of the invitation signing key is the derived seed;
        // it must never appear either.
        assert!(!body.contains(&encode_config(
            secret.derive_key(b"tinycloud/share-email/invitation-signing"),
            URL_SAFE_NO_PAD
        )));
    }

    #[rocket::async_test]
    async fn the_route_serves_the_derived_key_without_authentication() {
        let secret = secret();
        let expected = NodePublicKeys::derive(&secret);
        let rocket = rocket::build()
            .mount("/", rocket::routes![node_keys])
            .manage(expected.clone());
        let client = Client::tracked(rocket).await.expect("rocket client");

        let response = client
            .get("/.well-known/tinycloud/node-keys")
            .dispatch()
            .await;

        assert_eq!(response.status(), rocket::http::Status::Ok);
        let body: NodePublicKeys = response.into_json().await.expect("json body");
        assert_eq!(body, expected);
    }

    /// TC-359: the whole point of the route is that it reports the key the
    /// node derived at boot, whatever the key *source* was. Production runs
    /// `Keys::Dstack`, so drive `resolve_keys` through a dstack-shaped
    /// configuration — a real `Keys::Dstack` config against a dstack
    /// `GetKey` responder — and assert the route publishes that key.
    #[cfg(feature = "dstack")]
    #[rocket::async_test]
    // `resolve_keys` is async and the dstack socket path is process-global
    // environment state, so the env lock has to span the await. The guard is
    // the codebase's standard serializer for env-mutating tests.
    #[allow(clippy::await_holding_lock)]
    async fn the_route_publishes_the_dstack_derived_key() {
        use std::path::PathBuf;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixListener;

        // The KMS-derived bytes. Deliberately unlike any static secret the
        // process could read from its own environment.
        const KMS_KEY: [u8; 32] = [
            0xd3, 0x51, 0x0c, 0xa7, 0x9e, 0x22, 0x64, 0xbb, 0x17, 0x8f, 0x40, 0x05, 0xe1, 0x3a,
            0x9d, 0x76, 0x2c, 0x88, 0xf3, 0x61, 0x0b, 0x4e, 0xa5, 0xd0, 0x39, 0x77, 0x12, 0xc6,
            0x8a, 0x5b, 0xe4, 0x30,
        ];

        let directory = tempfile::tempdir().expect("tempdir for the dstack socket");
        let socket: PathBuf = directory.path().join("dstack.sock");
        let listener = UnixListener::bind(&socket).expect("bind dstack socket");
        let responder = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("dstack connection");
            let mut request = Vec::new();
            stream
                .read_to_end(&mut request)
                .await
                .expect("read GetKey request");
            assert!(
                String::from_utf8_lossy(&request).starts_with("POST /GetKey "),
                "the node must ask dstack to derive the key"
            );
            let body = format!("{{\"key\":\"{}\"}}", hex::encode(KMS_KEY));
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .expect("write GetKey response");
            stream.shutdown().await.expect("close dstack connection");
        });

        let _lock = crate::test_support::env_lock();
        let _endpoint = crate::test_support::EnvGuard::set(
            "DSTACK_SIMULATOR_ENDPOINT",
            socket.display().to_string(),
        );

        let resolved = crate::resolve_keys(&crate::config::Keys::Dstack)
            .await
            .expect("dstack key resolution");
        responder.await.expect("dstack responder");

        let rocket = rocket::build()
            .mount("/", rocket::routes![node_keys])
            .manage(NodePublicKeys::derive(&resolved));
        let client = Client::tracked(rocket).await.expect("rocket client");
        let body: NodePublicKeys = client
            .get("/.well-known/tinycloud/node-keys")
            .dispatch()
            .await
            .into_json()
            .await
            .expect("json body");

        let expected = StaticSecret::new(KMS_KEY.to_vec()).expect("32-byte KMS key");
        assert_eq!(
            body.share_invitation_public_key,
            encode_config(expected.share_invitation_public_key(), URL_SAFE_NO_PAD),
            "a dstack node must publish the key dstack derived, not a static-secret key"
        );
        assert_eq!(body.node_did, expected.node_did());
    }
}
