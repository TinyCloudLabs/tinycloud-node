//! TC-887: `tinycloud --validate-config` (the deploy preflight) refuses every
//! at-rest configuration that the node's startup refuses, without opening a
//! key, database or socket. Runs the real binary.

use std::process::Command;

/// Throwaway root keys, never real ones.
fn key(seed: u8) -> String {
    let bytes: Vec<u8> = (0..32u8)
        .map(|b| b.wrapping_mul(5).wrapping_add(seed))
        .collect();
    base64::encode_config(bytes, base64::STANDARD)
}

/// Runs `--validate-config` with only `vars` (plus PATH) in the environment.
fn validate(vars: &[(&str, &str)]) -> (bool, String) {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_tinycloud"))
        .arg("--validate-config")
        .current_dir(dir.path())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("TINYCLOUD_STORAGE__DATADIR", dir.path().join("data"))
        .envs(vars.iter().copied())
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout).into_owned()
        + &String::from_utf8_lossy(&output.stderr);
    (output.status.success(), text)
}

#[test]
fn validate_config_refuses_what_startup_refuses() {
    let k = key(3);
    let env_root = [
        ("TINYCLOUD_AT_REST__ROOT_SOURCE", "env"),
        ("TINYCLOUD_AT_REST_ROOT_KEY", k.as_str()),
    ];
    let (ok, out) = validate(&env_root);
    assert!(ok, "a valid env root must validate: {out}");

    // Encrypt validates exactly when this build's storage seals every write.
    let encrypt: Vec<(&str, &str)> = env_root
        .iter()
        .copied()
        .chain([("TINYCLOUD_AT_REST__MODE", "encrypt")])
        .collect();
    let (ok, out) = validate(&encrypt);
    assert_eq!(
        ok,
        tinycloud::at_rest::STORAGE_SEALS_EVERY_WRITE,
        "encrypt: {out}"
    );
    if !ok {
        assert!(out.contains("seal path"), "{out}");
    }

    type Case<'a> = (&'a str, Vec<(&'a str, &'a str)>, &'a str);
    let refused: [Case; 3] = [
        (
            "env root with escrow_none",
            vec![("TINYCLOUD_AT_REST__ESCROW_NONE", "true")],
            "has no escrow",
        ),
        (
            "env root with software escrow holders",
            vec![("TINYCLOUD_AT_REST__ESCROW__ALLOW_SOFTWARE", "true")],
            "has no escrow",
        ),
        (
            "a TEE declared by the TEE mode, whose guest agent is absent",
            vec![
                ("TINYCLOUD_TEE__MODE", "Dstack"),
                ("DSTACK_SIMULATOR_ENDPOINT", "/nonexistent/dstack.sock"),
            ],
            "TEE",
        ),
    ];
    for (case, extra, needle) in refused {
        let vars: Vec<(&str, &str)> = env_root.iter().copied().chain(extra).collect();
        let (ok, out) = validate(&vars);
        assert!(!ok, "{case}: --validate-config accepted it: {out}");
        assert!(out.contains(needle), "{case}: {out}");
        assert!(!out.contains(&k), "{case}: the key was printed");
    }
}
