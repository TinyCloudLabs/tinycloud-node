use std::{env, path::PathBuf, process::ExitCode};

use m1_realdata_e2e::live_gate_verifier::{self, Mode};

fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);
    let Some(bundle) = args.next() else {
        eprintln!("usage: m1-gate-verify <raw-bundle> [--self-test]");
        return ExitCode::from(2);
    };
    let mode = match args.next().as_deref() {
        None => Mode::Verify,
        Some(value) if value == "--self-test" => Mode::VerifyAndMutationSelfTest,
        Some(_) => {
            eprintln!("usage: m1-gate-verify <raw-bundle> [--self-test]");
            return ExitCode::from(2);
        }
    };
    match live_gate_verifier::run(&PathBuf::from(bundle), mode) {
        Ok(report) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).expect("serialize report")
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("verification failed: {error:#}");
            ExitCode::FAILURE
        }
    }
}
