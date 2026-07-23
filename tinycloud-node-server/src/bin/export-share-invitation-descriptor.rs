use anyhow::{bail, Context, Result};
use base64::{encode_config, URL_SAFE_NO_PAD};
use serde::Serialize;
use std::env;
use tinycloud_core::keys::StaticSecret;

const NODE_ORIGIN: &str = "https://tee.node.tinycloud.xyz";
const NODE_AUDIENCE: &str = "did:web:tee.node.tinycloud.xyz";
const NODE_INVITATION_KID: &str = "did:web:tee.node.tinycloud.xyz#invitation-key-1";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicInvitationDescriptor {
    node_origin: &'static str,
    node_audience: &'static str,
    node_invitation_kid: &'static str,
    node_invitation_public_key: String,
    node_key_version: u8,
}

fn descriptor(secret: StaticSecret) -> PublicInvitationDescriptor {
    PublicInvitationDescriptor {
        node_origin: NODE_ORIGIN,
        node_audience: NODE_AUDIENCE,
        node_invitation_kid: NODE_INVITATION_KID,
        node_invitation_public_key: encode_config(
            secret.share_invitation_public_key(),
            URL_SAFE_NO_PAD,
        ),
        node_key_version: 1,
    }
}

fn main() -> Result<()> {
    let encoded = env::var("TINYCLOUD_KEYS_SECRET")
        .context("TINYCLOUD_KEYS_SECRET is required to derive the public descriptor")?;
    if encoded.trim() != encoded {
        bail!("TINYCLOUD_KEYS_SECRET must be canonical base64url");
    }
    let decoded = base64::decode_config(encoded, URL_SAFE_NO_PAD)
        .context("TINYCLOUD_KEYS_SECRET must be canonical base64url")?;
    if encode_config(&decoded, URL_SAFE_NO_PAD) != env::var("TINYCLOUD_KEYS_SECRET")? {
        bail!("TINYCLOUD_KEYS_SECRET must be canonical base64url");
    }
    let secret = StaticSecret::new(decoded).map_err(|bytes| {
        anyhow::anyhow!(
            "TINYCLOUD_KEYS_SECRET must be at least 32 bytes, got {}",
            bytes.len()
        )
    })?;
    serde_json::to_writer(std::io::stdout(), &descriptor(secret))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exports_only_the_canonical_public_descriptor() {
        let descriptor = serde_json::to_value(descriptor(
            StaticSecret::new(vec![0x5a; 32]).expect("valid test secret"),
        ))
        .expect("serialize descriptor");

        assert_eq!(descriptor.as_object().expect("descriptor object").len(), 5);
        assert_eq!(descriptor["nodeOrigin"], NODE_ORIGIN);
        assert_eq!(descriptor["nodeAudience"], NODE_AUDIENCE);
        assert_eq!(descriptor["nodeInvitationKid"], NODE_INVITATION_KID);
        assert_eq!(descriptor["nodeKeyVersion"], 1);
        assert_eq!(
            descriptor["nodeInvitationPublicKey"]
                .as_str()
                .expect("public key")
                .len(),
            43
        );
        assert!(!descriptor.to_string().contains("WlpaWlpa"));
    }
}
