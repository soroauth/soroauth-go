//! Bakes the stellar-xdr version Cargo actually resolved into the binary.
//!
//! The harness refuses to run unless that version is the pinned one, and it
//! cannot read it out of Cargo.lock at runtime (the file is not shipped with
//! the binary), so the build script passes it through as a compile-time
//! environment variable. If the lockfile is absent — a fresh checkout that has
//! not resolved yet — the value is "unknown" and the runtime check refuses; it
//! never defaults to the pinned value, because that would defeat the check.

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=Cargo.lock");

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by cargo");
    let lock_path = Path::new(&manifest_dir).join("Cargo.lock");
    let lock = fs::read_to_string(lock_path).unwrap_or_default();

    let version = stellar_xdr_version(&lock).unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=SOROAUTH_STELLAR_XDR_VERSION={version}");
}

/// Returns the version of the `stellar-xdr` package in a Cargo.lock, if any.
fn stellar_xdr_version(lock: &str) -> Option<String> {
    let mut lines = lock.lines();
    while let Some(line) = lines.next() {
        if line.trim() != "name = \"stellar-xdr\"" {
            continue;
        }
        for next in lines.by_ref() {
            let trimmed = next.trim();
            if let Some(value) = trimmed.strip_prefix("version = ") {
                return Some(value.trim_matches('"').to_string());
            }
            // The next package starts before a version was seen: give up on
            // this entry rather than reading another package's version.
            if trimmed == "[[package]]" {
                break;
            }
        }
    }
    None
}
