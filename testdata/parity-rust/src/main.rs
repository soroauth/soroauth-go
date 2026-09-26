//! Command-line entry point for the Rust stellar-xdr parity harness.
//!
//! Reads every golden vector, recomputes its preimage and payload with the
//! stellar-xdr crate, and compares. Exit status is 0 only when at least one
//! vector was checked and none disagreed; 1 for a mismatch or a vacuous run;
//! 2 for a usage error or a build against the wrong stellar-xdr version.

use std::env;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use soroauth_parity_rust::{report, require_pinned, run, STELLAR_XDR_VERSION};

fn default_vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vectors")
}

const USAGE: &str = "\
usage: parity [--vectors <dir>]

Recomputes the golden vectors' preimages and payloads with the Rust
stellar-xdr crate and compares them against the recorded values.

  --vectors <dir>  directory holding the golden vector JSON files
                   (default: testdata/vectors, resolved from this crate)
";

fn main() -> ExitCode {
    let mut vectors_dir = default_vectors_dir();
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--vectors" => match args.next() {
                Some(value) => vectors_dir = PathBuf::from(value),
                None => {
                    eprintln!("parity harness: --vectors needs a directory");
                    return ExitCode::from(2);
                }
            },
            "-h" | "--help" => {
                print!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("parity harness: unknown argument {other:?}\n\n{USAGE}");
                return ExitCode::from(2);
            }
        }
    }

    if let Err(error) = require_pinned() {
        eprintln!("parity harness: {error}");
        return ExitCode::from(2);
    }

    println!("Rust stellar-xdr {STELLAR_XDR_VERSION} parity harness");
    println!("vectors: {}", vectors_dir.display());

    let results = match run(&vectors_dir) {
        Ok(results) => results,
        Err(error) => {
            eprintln!("parity harness: {error}");
            return ExitCode::from(2);
        }
    };

    let stdout = io::stdout();
    let stderr = io::stderr();
    let mut out = stdout.lock();
    let mut err = stderr.lock();
    let code = report(&results, &mut out, &mut err);
    let _ = out.flush();
    let _ = err.flush();
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}
