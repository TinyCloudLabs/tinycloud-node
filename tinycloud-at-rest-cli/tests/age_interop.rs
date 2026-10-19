//! Interop with the stock `age` CLI (Go reference implementation).
//!
//! Needs `AGE_BIN_DIR` pointing at a directory with `age` and `age-keygen`
//! (CI downloads a sha256-pinned age v1.3.2). Skips locally when unset; in
//! CI (`CI` set) a missing directory is a failure, never a silent pass.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use age_core::format::{FileKey, Stanza};
use base64::Engine;
use hpke::Deserializable;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use tinycloud_at_rest_escrow::{Ark, ArkId, EscrowBundle, HolderRecipient, RecipientPolicy};

const BIN: &str = env!("CARGO_BIN_EXE_tinycloud-at-rest");

fn age_dir(test: &str) -> Option<PathBuf> {
    match std::env::var_os("AGE_BIN_DIR") {
        Some(d) if !d.is_empty() => Some(PathBuf::from(d)),
        _ => {
            assert!(
                std::env::var_os("CI").is_none(),
                "{test} needs AGE_BIN_DIR in CI"
            );
            eprintln!("skipping {test}: AGE_BIN_DIR is unset");
            None
        }
    }
}

fn pipe(cmd: &mut Command, input: &[u8]) -> std::process::Output {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn stock_age_decrypts_shares_and_the_cli_accepts_them() {
    let Some(age) = age_dir("stock_age_decrypts_shares_and_the_cli_accepts_them") else {
        return;
    };
    let dir = std::env::temp_dir().join(format!("tc887-interop-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let mut holders = Vec::new();
    for name in ["sam", "hunter", "safe"] {
        let key = dir.join(format!("{name}.key"));
        let out = Command::new(age.join("age-keygen"))
            .arg("-o")
            .arg(&key)
            .output()
            .unwrap();
        assert!(out.status.success());
        let text = std::fs::read_to_string(&key).unwrap();
        let recipient = text
            .lines()
            .find_map(|l| l.strip_prefix("# public key: "))
            .unwrap()
            .to_owned();
        holders.push(HolderRecipient {
            holder: name.into(),
            recipient,
        });
    }
    let bundle = EscrowBundle::create(
        &Ark::generate(),
        ArkId::generate(),
        1,
        &holders,
        RecipientPolicy::AllowSoftware,
    )
    .unwrap();
    let bundle_path = dir.join("bundle.json");
    std::fs::write(&bundle_path, serde_json::to_vec(&bundle).unwrap()).unwrap();

    for (i, h) in holders.iter().enumerate() {
        // extract-share → stock age -d → check-share.
        let share = Command::new(BIN)
            .args([
                "extract-share",
                "--allow-software",
                "--holder",
                &h.holder,
                "--bundle",
            ])
            .arg(&bundle_path)
            .output()
            .unwrap();
        assert!(share.status.success());
        let share_file = dir.join(format!("{}.age", h.holder));
        std::fs::write(&share_file, &share.stdout).unwrap();
        let plain = Command::new(age.join("age"))
            .arg("-d")
            .arg("-i")
            .arg(dir.join(format!("{}.key", h.holder)))
            .arg(&share_file)
            .output()
            .unwrap();
        assert!(
            plain.status.success(),
            "{}",
            String::from_utf8_lossy(&plain.stderr)
        );
        let checked = pipe(
            Command::new(BIN)
                .args(["check-share", "--allow-software", "--bundle"])
                .arg(&bundle_path),
            &plain.stdout,
        );
        let stderr = String::from_utf8_lossy(&checked.stderr);
        assert!(checked.status.success(), "{stderr}");
        assert!(
            stderr.contains(&format!("share {} ({})", i + 1, h.holder)),
            "{stderr}"
        );

        // Another holder's identity can't open it.
        let other = holders[(i + 1) % 3].holder.clone();
        let wrong = Command::new(age.join("age"))
            .arg("-d")
            .arg("-i")
            .arg(dir.join(format!("{other}.key")))
            .arg(&share_file)
            .output()
            .unwrap();
        assert!(!wrong.status.success());
    }
}

type Kem = hpke::kem::DhP256HkdfSha256;

/// A software P-256 identity for `p256tag` stanzas (as a hardware key's
/// plugin would open them).
struct TagIdentity(<Kem as hpke::Kem>::PrivateKey);

impl age::Identity for TagIdentity {
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, age::DecryptError>> {
        if stanza.tag != "p256tag" || stanza.args.len() != 2 {
            return None;
        }
        let enc = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(&stanza.args[1])
            .ok()?;
        let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&enc).ok()?;
        let key = age_core::primitives::hpke_open::<Kem>(
            &enc,
            &self.0,
            b"age-encryption.org/p256tag",
            &stanza.body,
        )
        .ok()?;
        let key: [u8; 16] = key.try_into().ok()?;
        Some(Ok(FileKey::new(Box::new(key))))
    }
}

#[test]
fn stock_age_p256tag_output_opens_with_the_p256_key() {
    // Cross-implementation vector: Go age encrypts to an age1tag1 recipient;
    // the Rust stack the TEE uses (age-core HPKE) opens it with the key.
    let Some(age) = age_dir("stock_age_p256tag_output_opens_with_the_p256_key") else {
        return;
    };
    let sk = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let hrp = bech32::Hrp::parse("age1tag").unwrap();
    let recipient =
        age_core::primitives::bech32_encode(hrp, sk.public_key().to_encoded_point(true).as_bytes());
    let message = b"tinycloud p256tag interop";
    let out = pipe(
        Command::new(age.join("age")).args(["-e", "-r", &recipient]),
        message,
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let identity = TagIdentity(<Kem as hpke::Kem>::PrivateKey::from_bytes(&sk.to_bytes()).unwrap());
    let decryptor = age::Decryptor::new_buffered(&out.stdout[..]).unwrap();
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .unwrap();
    let mut plain = Vec::new();
    reader.read_to_end(&mut plain).unwrap();
    assert_eq!(plain, message);
}
