//! Binary-level tests: what a holder sees and the exit code they get.
//! 0 OK, 1 REFUSED, 3 ERROR (input could not be read).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use tinycloud_at_rest_escrow::{
    binding_digest, recovery_binding, Ark, ArkId, EscrowBundle, HolderRecipient, RecipientPolicy,
    RecoveryIdentity, RecoveryInfo, SharePayload, RECOVERY_INFO_VERSION,
};

const BIN: &str = env!("CARGO_BIN_EXE_tinycloud-at-rest");
const NONCE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

struct Fixture {
    dir: PathBuf,
    ids: Vec<age::x25519::Identity>,
    ark: Ark,
    ark_id: ArkId,
    holders: Vec<HolderRecipient>,
    bundle: EscrowBundle,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("tc887-cli-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ids: Vec<_> = (0..3).map(|_| age::x25519::Identity::generate()).collect();
        let holders: Vec<HolderRecipient> = ["sam", "hunter", "safe"]
            .iter()
            .zip(&ids)
            .map(|(h, id)| HolderRecipient {
                holder: h.to_string(),
                recipient: id.to_public().to_string(),
            })
            .collect();
        let (ark, ark_id) = (Ark::generate(), ArkId::generate());
        let bundle =
            EscrowBundle::create(&ark, ark_id, 1, &holders, RecipientPolicy::AllowSoftware)
                .unwrap();
        let f = Self {
            dir,
            ids,
            ark,
            ark_id,
            holders,
            bundle,
        };
        f.write("bundle.json", &serde_json::to_vec(&f.bundle).unwrap());
        f
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let p = self.path(name);
        std::fs::write(&p, bytes).unwrap();
        p
    }

    /// What holder `i` gets from `age -d`.
    fn decrypted(&self, bundle: &EscrowBundle, i: usize) -> Vec<u8> {
        let armored = &bundle.shares[i].ciphertext;
        let decryptor =
            age::Decryptor::new_buffered(age::armor::ArmoredReader::new(armored.as_bytes()))
                .unwrap();
        let mut reader = decryptor
            .decrypt(std::iter::once(&self.ids[i] as &dyn age::Identity))
            .unwrap();
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        out
    }

    fn info(&self, mode: &str, quote: Option<&str>) -> RecoveryInfo {
        let tee = RecoveryIdentity::generate();
        let efp = self.bundle.fingerprint();
        let binding = recovery_binding(&tee.recipient(), &efp, NONCE);
        RecoveryInfo {
            version: RECOVERY_INFO_VERSION,
            mode: mode.into(),
            state: "unlocked".into(),
            ark_id: self.bundle.ark_id,
            generation: 1,
            efp,
            canary_fp: self.bundle.canary_fp,
            recovery_recipient: tee.recipient(),
            binding_sha256: binding_digest(&binding),
            binding,
            quote: quote.map(str::to_owned),
            event_log: Some("[]".into()),
            shares_held: vec![],
        }
    }
}

fn run(args: &[&str], stdin: Option<&[u8]>) -> Output {
    let mut child = Command::new(BIN)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut pipe = child.stdin.take().unwrap();
        if let Some(bytes) = stdin {
            pipe.write_all(bytes).unwrap();
        }
    }
    child.wait_with_output().unwrap()
}

fn p(path: &Path) -> &str {
    path.to_str().unwrap()
}

#[track_caller]
fn expect(out: &Output, code: i32, needle: &str) {
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(code), "stderr: {stderr}");
    assert!(stderr.contains(needle), "{stderr:?} lacks {needle:?}");
}

#[test]
fn software_holders_are_refused_unless_allowed_and_then_flagged() {
    let f = Fixture::new("software");
    let b = f.path("bundle.json");
    expect(
        &run(&["inspect", "--bundle", p(&b)], None),
        1,
        "software keys",
    );
    let out = run(&["inspect", "--bundle", p(&b), "--allow-software"], None);
    expect(&out, 0, "!!! WARNING");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(&f.bundle.fingerprint().to_string()));
    assert_eq!(stdout.matches("X25519!").count(), 3);
}

#[test]
fn expect_efp_guards_every_bundle_command() {
    let f = Fixture::new("expect");
    let b = f.path("bundle.json");
    let efp = f.bundle.fingerprint().to_string();
    let other = "0".repeat(64);
    for cmd in ["inspect", "check-share"] {
        expect(
            &run(
                &[
                    cmd,
                    "--bundle",
                    p(&b),
                    "--allow-software",
                    "--expect-efp",
                    &other,
                ],
                Some(b"x"),
            ),
            1,
            "not the expected",
        );
    }
    expect(
        &run(
            &[
                "extract-share",
                "--bundle",
                p(&b),
                "--allow-software",
                "--expect-efp",
                &other,
                "--holder",
                "sam",
            ],
            None,
        ),
        1,
        "stale",
    );
    // Case-insensitive.
    let upper = efp.to_uppercase();
    let out = run(
        &[
            "inspect",
            "--bundle",
            p(&b),
            "--allow-software",
            "--expect-efp",
            &upper,
        ],
        None,
    );
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn check_share_names_the_real_problem() {
    let f = Fixture::new("check");
    let b = f.path("bundle.json");
    let args = ["check-share", "--bundle", p(&b), "--allow-software"];

    let good = f.decrypted(&f.bundle, 1);
    expect(&run(&args, Some(&good)), 0, "share 2 (hunter)");

    // `age -d` failed and printed nothing.
    expect(&run(&args, Some(b"")), 3, "did `age -d` fail");

    // A share from an earlier split of the same key: commitment mismatch, with a hint.
    let resplit = EscrowBundle::create(
        &f.ark,
        f.ark_id,
        1,
        &f.holders,
        RecipientPolicy::AllowSoftware,
    )
    .unwrap();
    let old = f.decrypted(&resplit, 0);
    expect(&run(&args, Some(&old)), 1, "re-split");

    // Tampered bytes.
    let mut bad = good.clone();
    bad[40] ^= 1;
    expect(&run(&args, Some(&bad)), 1, "commitment");
    assert!(SharePayload::decode(&bad).is_ok());
}

#[test]
fn input_problems_are_errors_not_refusals() {
    let f = Fixture::new("input");
    let b = f.path("bundle.json");
    expect(
        &run(&["inspect", "--bundle", p(&f.path("missing.json"))], None),
        3,
        "ERROR",
    );
    expect(
        &run(
            &[
                "extract-share",
                "--bundle",
                p(&b),
                "--allow-software",
                "--holder",
                "mallory",
            ],
            None,
        ),
        3,
        "no holder \"mallory\"",
    );
    // A newer bundle format is named as such.
    let mut v2: serde_json::Value = serde_json::to_value(&f.bundle).unwrap();
    v2["version"] = 2.into();
    v2["kdf"] = "x".into();
    let v2 = f.write("v2.json", &serde_json::to_vec(&v2).unwrap());
    expect(&run(&["inspect", "--bundle", p(&v2)], None), 1, "version 2");
    // A bad download (HTML, truncated JSON) is an input error, not a refusal.
    let html = f.write("html.json", b"<html>502 Bad Gateway</html>");
    expect(&run(&["inspect", "--bundle", p(&html)], None), 3, "ERROR");
    // A recovery response in an unknown state is malformed input too.
    let mut info = serde_json::to_value(f.info("dstack", Some("00"))).unwrap();
    info["state"] = "rebooting".into();
    let r = f.write("weird.json", &serde_json::to_vec(&info).unwrap());
    let out = run(
        &[
            "verify-node",
            "--bundle",
            p(&b),
            "--allow-software",
            "--recovery",
            p(&r),
            "--nonce",
            NONCE,
            "--trust",
            p(&b),
        ],
        None,
    );
    expect(&out, 3, "state must be");
}

#[test]
fn verify_node_reports_local_causes_before_any_network() {
    let f = Fixture::new("node");
    let b = f.path("bundle.json");
    let trust = f.write(
        "trust.json",
        serde_json::json!({
            "app_id": "1".repeat(40), "compose_hash": "2".repeat(64),
            "mrtd": "a".repeat(96), "rtmr0": "a".repeat(96),
            "rtmr1": "a".repeat(96), "rtmr2": "a".repeat(96),
        })
        .to_string()
        .as_bytes(),
    );
    // An unroutable PCCS: reaching it would be a network error, so any local
    // refusal must come first.
    let node = |info: &RecoveryInfo, nonce: &str| {
        let r = f.write("recovery.json", &serde_json::to_vec(info).unwrap());
        run(
            &[
                "verify-node",
                "--bundle",
                p(&b),
                "--allow-software",
                "--recovery",
                p(&r),
                "--nonce",
                nonce,
                "--trust",
                p(&trust),
                "--pccs-url",
                "http://127.0.0.1:9",
            ],
            None,
        )
    };
    expect(
        &node(&f.info("classic", Some("00")), NONCE),
        1,
        "not in a TEE",
    );
    expect(&node(&f.info("dstack", None), NONCE), 1, "no TDX quote");
    expect(&node(&f.info("dstack", Some("zz")), NONCE), 1, "not hex");
    expect(
        &node(&f.info("dstack", Some("00")), "short"),
        1,
        "at least 22",
    );
    expect(
        &node(
            &f.info("dstack", Some("00")),
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        ),
        1,
        "not for your nonce",
    );
    let mut stale = f.info("dstack", Some("00"));
    stale.efp = tinycloud_at_rest_escrow::Digest32([9; 32]);
    expect(&node(&stale, NONCE), 1, "stale");
    // Everything local passes: now the PCCS is contacted and fails as input.
    expect(&node(&f.info("dstack", Some("00")), NONCE), 3, "collateral");
    // An older/newer node response format is named.
    let r = f.write("recovery.json", br#"{"version":2,"mode":"dstack"}"#);
    let out = run(
        &[
            "verify-node",
            "--bundle",
            p(&b),
            "--allow-software",
            "--recovery",
            p(&r),
            "--nonce",
            NONCE,
            "--trust",
            p(&trust),
        ],
        None,
    );
    expect(&out, 1, "recovery response is version 2");
}

#[test]
fn record_efp_never_claims_authenticity() {
    use tinycloud_at_rest_escrow::VerificationRecord;
    let f = Fixture::new("record");
    let b = f.path("bundle.json");
    let shares: Vec<SharePayload> = (0..3)
        .map(|i| f.bundle.open_share(&f.decrypted(&f.bundle, i)).unwrap())
        .collect();
    let unlock = f.bundle.test_unlock(&f.ark, &shares).unwrap();
    let record =
        VerificationRecord::seal(&f.ark, &f.bundle, &unlock, None, None, "t".into()).unwrap();
    let mut forged = serde_json::to_value(&record).unwrap();
    forged["mac"] = "0".repeat(64).into();
    forged["app_id"] = "attacker".into();
    let forged = f.write("forged.json", &serde_json::to_vec(&forged).unwrap());
    let out = run(
        &[
            "record-efp",
            "--bundle",
            p(&b),
            "--allow-software",
            "--record",
            p(&forged),
        ],
        None,
    );
    expect(&out, 0, "NOT AUTHENTICATED");
    assert!(!String::from_utf8_lossy(&out.stderr).contains("OK"));

    // A record for another escrow is refused outright.
    let other = EscrowBundle::create(
        &f.ark,
        f.ark_id,
        1,
        &f.holders,
        RecipientPolicy::AllowSoftware,
    )
    .unwrap();
    let other = f.write("other.json", &serde_json::to_vec(&other).unwrap());
    let real = f.write("record.json", &serde_json::to_vec(&record).unwrap());
    expect(
        &run(
            &[
                "record-efp",
                "--bundle",
                p(&other),
                "--allow-software",
                "--record",
                p(&real),
            ],
            None,
        ),
        1,
        "different escrow bundle",
    );
}

#[test]
fn self_test_round_trips_and_refuses_software_by_default() {
    let f = Fixture::new("selftest");
    let id = &f.ids[0];
    let recipient = id.to_public().to_string();
    expect(
        &run(
            &["self-test", "--recipient", &recipient, "--out", p(&f.dir)],
            None,
        ),
        1,
        "software keys",
    );
    let out = run(
        &[
            "self-test",
            "--recipient",
            &recipient,
            "--allow-software",
            "--out",
            // A directory that doesn't exist yet: self-test creates it.
            p(&f.dir.join("st/new")),
        ],
        None,
    );
    expect(&out, 0, "THROWAWAY");
    let armored = std::fs::read_to_string(f.dir.join("st/new/selftest-share.age")).unwrap();
    let decryptor =
        age::Decryptor::new_buffered(age::armor::ArmoredReader::new(armored.as_bytes())).unwrap();
    let mut plain = Vec::new();
    decryptor
        .decrypt(std::iter::once(id as &dyn age::Identity))
        .unwrap()
        .read_to_end(&mut plain)
        .unwrap();
    let bundle = f.dir.join("st/new/selftest-bundle.json");
    expect(
        &run(
            &["check-share", "--bundle", p(&bundle), "--allow-software"],
            Some(&plain),
        ),
        0,
        "share 1 (selftest)",
    );
}
