//! One-off (TC-971): print the public identities a node started with a static
//! `TINYCLOUD_KEYS_SECRET` presents, so live delegations naming them can be
//! counted before the secret is deleted. Run once by
//! `.github/workflows/tc971-static-identity-once.yml`, then deleted with it.
//!
//! The secret is decoded exactly as `key_provider::resolve_static_env_secret`
//! does (trimmed, url-safe base64 without padding) and the identities come
//! from the same `StaticSecret` derivations the node uses. Errors carry labels
//! only, never input bytes.

use base64::{encode_config, URL_SAFE_NO_PAD};
use std::{env, process::ExitCode};
use tinycloud_core::keys::StaticSecret;

const SECRET_ENV: &str = "TINYCLOUD_KEYS_SECRET";

fn public_identity_lines(secret: &StaticSecret) -> String {
    let invitation = encode_config(secret.share_invitation_public_key(), URL_SAFE_NO_PAD);
    format!(
        "node_did={}\nrenewer_did={}\ninvitation_key_prefix={}\n",
        secret.node_did(),
        secret.renewal_did(),
        &invitation[..8],
    )
}

fn secret_from_env() -> Result<StaticSecret, &'static str> {
    let rendered = env::var(SECRET_ENV).map_err(|_| "TINYCLOUD_KEYS_SECRET is unset or not UTF-8")?;
    let decoded = base64::decode_config(rendered.trim(), URL_SAFE_NO_PAD)
        .map_err(|_| "TINYCLOUD_KEYS_SECRET is not url-safe base64")?;
    StaticSecret::new(decoded).map_err(|_| "TINYCLOUD_KEYS_SECRET decodes to fewer than 32 bytes")
}

fn main() -> ExitCode {
    match secret_from_env() {
        Ok(secret) => {
            print!("{}", public_identity_lines(&secret));
            ExitCode::SUCCESS
        }
        Err(label) => {
            eprintln!("error: {label}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prints_exactly_the_three_public_lines() {
        let raw = vec![0x5a; 32];
        let secret = StaticSecret::new(raw.clone()).expect("valid test secret");
        let out = public_identity_lines(&secret);
        let lines: Vec<&str> = out.lines().collect();

        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], format!("node_did={}", secret.node_did()));
        assert_eq!(lines[1], format!("renewer_did={}", secret.renewal_did()));
        assert!(lines[0].starts_with("node_did=did:key:z6Mk"));
        assert!(lines[1].starts_with("renewer_did=did:key:z6Mk"));
        assert_ne!(lines[0]["node_did=".len()..], lines[1]["renewer_did=".len()..]);
        let prefix = lines[2].strip_prefix("invitation_key_prefix=").expect("prefix line");
        assert_eq!(prefix.len(), 8);
        assert!(encode_config(secret.share_invitation_public_key(), URL_SAFE_NO_PAD)
            .starts_with(prefix));
        assert!(!out.contains(&encode_config(&raw, URL_SAFE_NO_PAD)));
    }
}
