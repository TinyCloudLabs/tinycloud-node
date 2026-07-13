use std::{env, path::PathBuf, process::ExitCode};

use m1_realdata_e2e::live_gate_verifier::{self, Mode};

fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);
    let Some(bundle) = args.next() else {
        usage();
        return ExitCode::from(2);
    };
    let mut mode = Mode::Verify;
    let mut expected_node_sha = None;
    while let Some(arg) = args.next() {
        if arg == "--self-test" {
            mode = Mode::VerifyAndMutationSelfTest;
        } else if arg == "--expected-node-sha" {
            expected_node_sha = args.next();
            if expected_node_sha.is_none() {
                usage();
                return ExitCode::from(2);
            }
        } else {
            usage();
            return ExitCode::from(2);
        }
    }
    let expected_node_sha = expected_node_sha
        .or_else(|| env::var_os("M1_EXPECTED_NODE_SHA"))
        .and_then(|value| value.into_string().ok())
        .filter(|value| !value.is_empty());
    let Some(expected_node_sha) = expected_node_sha else {
        eprintln!("verification failed: --expected-node-sha or M1_EXPECTED_NODE_SHA is required");
        return ExitCode::FAILURE;
    };
    match live_gate_verifier::run(&PathBuf::from(bundle), mode, &expected_node_sha) {
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

fn usage() {
    eprintln!("usage: m1-gate-verify <raw-bundle> [--self-test] [--expected-node-sha <sha>]");
}
