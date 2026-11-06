//! JSON stdin/stdout adapter for callers such as OpenKey TypeScript.
//!
//! Input: {"bundle": AttestationBundle, "policy": AttestationPolicy,
//!         "expected_report_data": "<64-byte hex>"}.
//! Success: {"ok":true}, exit 0. Failure: {"ok":false,"error":"..."}, exit 2.
//! No command-line arguments or caller-supplied clock are accepted. Verification
//! uses the local wall clock; errors do not echo untrusted inputs or collateral.

use serde::Deserialize;
use std::io::{self, Read};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};
use tinycloud_attestation::{verify, AttestationBundle, AttestationPolicy};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    bundle: AttestationBundle,
    policy: AttestationPolicy,
    expected_report_data: String,
}

fn run() -> Result<(), &'static str> {
    if std::env::args_os().len() != 1 {
        return Err("no command-line arguments are accepted");
    }
    let mut input = Vec::new();
    io::stdin()
        .read_to_end(&mut input)
        .map_err(|_| "invalid attestation request")?;
    let request: Request =
        serde_json::from_slice(&input).map_err(|_| "invalid attestation request")?;
    let report_data = request
        .expected_report_data
        .strip_prefix("0x")
        .unwrap_or(&request.expected_report_data);
    let expected: [u8; 64] = hex::decode(report_data)
        .map_err(|_| "invalid attestation request")?
        .try_into()
        .map_err(|_| "invalid attestation request")?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is invalid")?
        .as_secs();
    verify(&request.bundle, &request.policy, &expected, now)
        .map_err(|_| "attestation verification failed")
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => {
            println!("{{\"ok\":true}}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            // Only fixed strings selected above reach output; no raw parser,
            // cryptographic errors, request values, or secrets are serialized.
            println!("{}", serde_json::json!({"ok": false, "error": error}));
            ExitCode::from(2)
        }
    }
}
