//! Synthetic transport tests. These do NOT establish DCAP-valid migration binding.
use super::*;
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::thread;

fn policy() -> AttestationPolicy {
    AttestationPolicy {
        app_id: "11223344".into(),
        compose_hashes: vec!["11".repeat(32)],
        kms_id: "aabb".into(),
        mrtd: "00".repeat(48),
        rtmr0: "00".repeat(48),
        rtmr1: "00".repeat(48),
        rtmr2: "00".repeat(48),
    }
}

fn target(root: &[u8]) -> TargetDocument {
    let mut fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../tinycloud-attestation/tests/fixtures/dstack-tdx-quote.json"
    ))
    .unwrap();
    // Preserve the recorded JS fixture; adapt byte arrays to Rust serde-human-bytes hex.
    for name in [
        "root_ca_crl",
        "pck_crl",
        "tcb_info_signature",
        "qe_identity_signature",
    ] {
        let bytes: Vec<u8> = serde_json::from_value(fixture["collateral"][name].clone()).unwrap();
        fixture["collateral"][name] = serde_json::Value::String(hex::encode(bytes));
    }
    let attestation = serde_json::from_value(serde_json::json!({
        "quote": fixture["getQuote"]["quote"],
        "event_log": serde_json::from_str::<serde_json::Value>(fixture["getQuote"]["event_log"].as_str().unwrap()).unwrap(),
        "collateral": fixture["collateral"],
    })).unwrap();
    let private = import_private_key(root).unwrap();
    TargetDocument {
        attestation,
        public_key: hex::encode(Kem::sk_to_pk(&private).to_bytes()),
    }
}

#[test]
fn full_variable_length_root_roundtrip_is_scoped_to_job() {
    let old = Zeroizing::new((0..80).collect::<Vec<u8>>());
    let new = [81u8; 48];
    let target = target(&new);
    let did = node_did(&old).unwrap();
    let sealed = seal_root(&old, &target, &policy(), &did).unwrap();
    let expected = derive_key(&old, b"test/job");
    let actual = open_for_job(&new, &target, &policy(), &did, &sealed, |root| {
        Ok(root.derive_key(b"test/job"))
    })
    .unwrap();
    assert_eq!(*expected, *actual);
    assert_ne!(*expected, *derive_key(&old[..32], b"test/job"));
}

#[test]
fn wrong_identity_key_transcript_and_ciphertext_never_run_job() {
    let old = [1u8; 64];
    let new = [2u8; 48];
    let mut target = target(&new);
    let did = node_did(&old).unwrap();
    let sealed = seal_root(&old, &target, &policy(), &did).unwrap();
    let reject = |new: &[u8], target: &TargetDocument, did: &str, sealed: &SealedRoot| {
        assert!(
            open_for_job(new, target, &policy(), did, sealed, |_| -> Result<()> {
                panic!("job must not run")
            })
            .is_err()
        );
    };
    reject(&new, &target, "did:key:wrong", &sealed);
    reject(&[3u8; 48], &target, &did, &sealed);
    target.attestation.quote.push_str("00");
    reject(&new, &target, &did, &sealed);
    target
        .attestation
        .quote
        .truncate(target.attestation.quote.len() - 2);
    let mut damaged: SealedRoot =
        serde_json::from_value(serde_json::to_value(&sealed).unwrap()).unwrap();
    damaged
        .ct
        .replace_range(0..2, if &sealed.ct[..2] == "00" { "01" } else { "00" });
    reject(&new, &target, &did, &damaged);
    damaged = serde_json::from_value(serde_json::to_value(&sealed).unwrap()).unwrap();
    damaged.old_did = "did:key:wrong".into();
    reject(&new, &target, &did, &damaged);
    damaged = serde_json::from_value(serde_json::to_value(&sealed).unwrap()).unwrap();
    damaged.version += 1;
    reject(&new, &target, &did, &damaged);
}

#[test]
fn report_binding_is_domain_separated_and_zero_padded() {
    let public = [7u8; 32];
    let binding = report_binding(&public, &policy()).unwrap();
    // Independently calculated with Python hashlib, not this crate's implementation.
    assert_eq!(
        hex::encode(&binding[..32]),
        "ba915b8c256f9ca338e9e333c15aa848f55884830e265dff399485f758337b84"
    );
    assert_eq!(&binding[32..], &[0u8; 32]);
    let mut bad = policy();
    bad.app_id = "not-hex".into();
    assert!(report_binding(&public, &bad).is_err());
}

#[test]
fn recorded_unbound_quote_is_rejected_before_export() {
    let target = target(&[2u8; 48]);
    assert!(verify_target(&target, &policy(), 1_781_000_000).is_err());
}

#[test]
fn node_did_matches_existing_node_startup_fixture() {
    // Existing node startup_identity.rs TC-1442 fixture, no tinycloud-core dependency.
    let root =
        hex::decode("54432d313434322064737461636b204765744b65792066697874757265212121").unwrap();
    assert_eq!(
        node_did(&root).unwrap(),
        "did:key:z6MkmRVxeLv23jCfiR5XQMt5yZsyP5rxoS8GD8RkWoo7BnBA"
    );
    assert!(node_did(&root[..31]).is_err());
}

#[test]
fn guest_get_key_preserves_all_bytes_and_uses_explicit_socket() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("guest.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let root = (0..80).collect::<Vec<u8>>();
    let response_root = root.clone();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).unwrap();
        let text = String::from_utf8(request).unwrap();
        assert!(text.starts_with("POST /GetKey HTTP/1.1\r\n"));
        let request: serde_json::Value =
            serde_json::from_str(text.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(
            request,
            serde_json::json!({"path":"tinycloud/keys/primary"})
        );
        let body = serde_json::json!({"key":hex::encode(response_root)}).to_string();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
    });
    let received = GuestClient::new(&socket).get_root().unwrap();
    assert_eq!(&**received, root.as_slice());
    server.join().unwrap();
}

#[test]
fn guest_errors_do_not_include_response_or_secret() {
    let raw = b"HTTP/1.1 500 Internal Error\r\nContent-Length: 18\r\n\r\nprivate-root-value";
    let error = response_body(raw).unwrap_err().to_string();
    assert!(!error.contains("private-root-value"));
    assert!(
        response_body(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n").is_err()
    );
}

#[test]
fn rfc9180_x25519_hkdf_sha256_aes256gcm_receiver_known_answer() {
    // RFC 9180 upstream CFRG test-vectors commit 5f503c5, included by hpke 0.12.0.
    let decode = |text| hex::decode(text).unwrap();
    let private = <Kem as KemTrait>::PrivateKey::from_bytes(&decode(
        "497b4502664cfea5d5af0b39934dac72242a74f8480451e1aee7d6a53320333d",
    ))
    .unwrap();
    let enc = <Kem as KemTrait>::EncappedKey::from_bytes(&decode(
        "6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256",
    ))
    .unwrap();
    let mut context = hpke::setup_receiver::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &private,
        &enc,
        &decode("4f6465206f6e2061204772656369616e2055726e"),
    )
    .unwrap();
    let plaintext = context.open(&decode("e5d84cd531cfb583096e7cfa9641bd3079cf3a91cda813c52deb5f512be9931980a41de125a925cdad859d5b7a"), &decode("436f756e742d30")).unwrap();
    assert_eq!(plaintext, b"Beauty is truth, truth beauty");
}

#[test]
fn transcript_framing_has_independent_known_answer() {
    let mut target = target(&[2u8; 48]);
    target.attestation.quote = "010203".into();
    let aad = transcript(&target, &policy(), "did:key:test").unwrap();
    // Python hashlib calculation of the documented length-prefixed AAD.
    assert_eq!(
        hex::encode(Sha256::digest(aad)),
        "bfdea0b1cf076cf4748f7e58532ad62dd8803653ccf5d86ff324f30963c85e5a"
    );
}

#[test]
fn rfc9180_sender_reproduces_upstream_encapsulation_and_ciphertext() {
    struct VectorRandom(Vec<u8>);
    impl rand::RngCore for VectorRandom {
        fn next_u32(&mut self) -> u32 {
            panic!("unexpected vector RNG call")
        }
        fn next_u64(&mut self) -> u64 {
            panic!("unexpected vector RNG call")
        }
        fn fill_bytes(&mut self, output: &mut [u8]) {
            assert_eq!(output.len(), self.0.len());
            output.copy_from_slice(&self.0);
            self.0.clear();
        }
        fn try_fill_bytes(&mut self, output: &mut [u8]) -> std::result::Result<(), rand::Error> {
            self.fill_bytes(output);
            Ok(())
        }
    }
    impl rand::CryptoRng for VectorRandom {}
    let decode = |text| hex::decode(text).unwrap();
    let mut rng = VectorRandom(decode(
        "2cd7c601cefb3d42a62b04b7a9041494c06c7843818e0ce28a8f704ae7ab20f9",
    ));
    let recipient = <Kem as KemTrait>::PublicKey::from_bytes(&decode(
        "430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c",
    ))
    .unwrap();
    let (enc, mut sender) = hpke::setup_sender::<Aead, Kdf, Kem, _>(
        &OpModeS::Base,
        &recipient,
        &decode("4f6465206f6e2061204772656369616e2055726e"),
        &mut rng,
    )
    .unwrap();
    assert_eq!(
        hex::encode(enc.to_bytes()),
        "6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256"
    );
    let ciphertext = sender
        .seal(b"Beauty is truth, truth beauty", &decode("436f756e742d30"))
        .unwrap();
    assert_eq!(hex::encode(ciphertext), "e5d84cd531cfb583096e7cfa9641bd3079cf3a91cda813c52deb5f512be9931980a41de125a925cdad859d5b7a");
}

#[test]
fn guest_refuses_unbounded_response_body() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("guest.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
            .unwrap();
    });
    assert!(GuestClient::new(socket).get_root().is_err());
    server.join().unwrap();
}
