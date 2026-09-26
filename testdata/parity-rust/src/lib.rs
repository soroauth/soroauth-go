//! Rust `stellar-xdr` parity harness for the soroauth golden vectors.
//!
//! The golden vectors in `../vectors/` prove that soroauth reproduces what
//! `@stellar/stellar-sdk` emits, byte for byte. They cannot prove that
//! agreement is *correct*: a bug shared by the Go library and the JS reference
//! would be frozen into the vectors and every test would keep passing.
//!
//! This harness closes that gap with the implementation closest to the host
//! itself: the [`stellar-xdr`](https://crates.io/crates/stellar-xdr) crate,
//! which is what `rs-soroban-env` decodes with. For every committed vector it
//! decodes `unsigned_entry_xdr`, rebuilds the `HashIDPreimage` from the entry,
//! `valid_until_ledger` and `network_passphrase`, and asserts:
//!
//! * the base64 marshalling of the preimage equals `preimage_xdr`;
//! * `sha256(preimage)` in hex equals `payload_hex`.
//!
//! It never writes to a vector. A disagreement is a failure to investigate, not
//! a value to update.
//!
//! Cases the recording side marked as having no preimage — the source-account
//! arms, which the transaction envelope authenticates instead — are skipped
//! **loudly**, named on stderr and counted, and a run that checked nothing
//! exits non-zero so the harness cannot pass by doing nothing.
//!
//! The reference is pinned exactly in `Cargo.toml` and `Cargo.lock`, and the
//! build script bakes the resolved version into the binary so `require_pinned`
//! can refuse to run against anything else.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};
use stellar_xdr::{
    Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization,
    HashIdPreimageSorobanAuthorizationWithAddress, Limits, ReadXdr, SorobanAuthorizationEntry,
    SorobanCredentials, SorobanAuthorizedInvocation, WriteXdr,
};

/// The exact stellar-xdr version this harness is pinned to. The value is baked
/// in by `build.rs` from `Cargo.lock`, never typed here.
pub const REQUIRED_STELLAR_XDR_VERSION: &str = "28.0.0";

/// The stellar-xdr version the binary was actually built against, read from
/// `Cargo.lock` by `build.rs`. It is `"unknown"` when the lockfile was absent.
pub const STELLAR_XDR_VERSION: &str = env!("SOROAUTH_STELLAR_XDR_VERSION");

/// The outcome of checking one vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The recomputed preimage and payload both matched the record.
    Match,
    /// One or both differed; `CaseResult::detail` says which and shows the bytes.
    Mismatch,
    /// The case has no preimage to recompute; `CaseResult::detail` says why.
    Skip,
}

/// The result of checking one vector.
#[derive(Debug, Clone)]
pub struct CaseResult {
    /// The vector's `name`, or its file name if the field is absent.
    pub name: String,
    /// What happened.
    pub status: Status,
    /// A human-readable reason for a mismatch or a skip; empty for a match.
    pub detail: String,
}

impl CaseResult {
    /// Whether the vector matched.
    pub fn is_match(&self) -> bool {
        self.status == Status::Match
    }

    /// Whether the vector disagreed with the reference.
    pub fn is_mismatch(&self) -> bool {
        self.status == Status::Mismatch
    }

    /// Whether the vector was skipped.
    pub fn is_skip(&self) -> bool {
        self.status == Status::Skip
    }
}

/// Checks that the binary was built against the pinned stellar-xdr version.
///
/// The build script sets `STELLAR_XDR_VERSION` from `Cargo.lock`; if it is not
/// exactly the pinned value, this returns the two versions in an error rather
/// than letting a parity result be attributed to an unknown reference.
pub fn require_pinned() -> Result<(), String> {
    if STELLAR_XDR_VERSION != REQUIRED_STELLAR_XDR_VERSION {
        return Err(format!(
            "the harness is built against stellar-xdr {STELLAR_XDR_VERSION}, \
             but is pinned to {REQUIRED_STELLAR_XDR_VERSION}; \
             run `cargo update -p stellar-xdr --precise {REQUIRED_STELLAR_XDR_VERSION}`"
        ));
    }
    Ok(())
}

/// Names a credential arm for human-readable output.
fn credential_type_name(credentials: &SorobanCredentials) -> &'static str {
    match credentials {
        SorobanCredentials::SourceAccount => "source_account",
        SorobanCredentials::Address(_) => "address",
        SorobanCredentials::AddressV2(_) => "address_v2",
        SorobanCredentials::AddressWithDelegates(_) => "address_with_delegates",
    }
}

/// SHA-256 of `data`, as the 32-byte array the XDR `Hash` wraps.
fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Rebuilds the `HashIDPreimage` for an entry, exactly as soroauth's `Preimage`
/// does: the expiration comes from `valid_until_ledger`, not from the value
/// stored on the entry, because the caller is about to write that value in.
///
/// The source-account arm has no preimage and is an error here; callers skip it
/// before reaching this function.
pub fn build_preimage(
    entry: &SorobanAuthorizationEntry,
    valid_until_ledger: u32,
    network_passphrase: &str,
) -> Result<HashIdPreimage, String> {
    let network_id = Hash(sha256(network_passphrase.as_bytes()));
    let invocation = entry.root_invocation.clone();

    match &entry.credentials {
        SorobanCredentials::SourceAccount => {
            Err("source-account credentials carry no preimage".to_string())
        }
        // ENVELOPE_TYPE_SOROBAN_AUTHORIZATION (9): the address is not in the
        // signed bytes. CAP-46-11.
        SorobanCredentials::Address(credentials) => {
            Ok(HashIdPreimage::SorobanAuthorization(
                HashIdPreimageSorobanAuthorization {
                    network_id,
                    nonce: credentials.nonce,
                    signature_expiration_ledger: valid_until_ledger,
                    invocation,
                },
            ))
        }
        // ENVELOPE_TYPE_SOROBAN_AUTHORIZATION_WITH_ADDRESS (10): the top-level
        // address is in the signed bytes. CAP-71-01.
        SorobanCredentials::AddressV2(credentials) => Ok(with_address(
            network_id,
            credentials.nonce,
            valid_until_ledger,
            credentials.address.clone(),
            invocation,
        )),
        // The delegates arm signs the same address-bound payload as V2, bound
        // to the top-level address. CAP-71-01.
        SorobanCredentials::AddressWithDelegates(credentials) => Ok(with_address(
            network_id,
            credentials.address_credentials.nonce,
            valid_until_ledger,
            credentials.address_credentials.address.clone(),
            invocation,
        )),
    }
}

/// Builds the address-bound preimage variant shared by the V2 and delegates
/// arms.
fn with_address(
    network_id: Hash,
    nonce: i64,
    signature_expiration_ledger: u32,
    address: stellar_xdr::ScAddress,
    invocation: SorobanAuthorizedInvocation,
) -> HashIdPreimage {
    HashIdPreimage::SorobanAuthorizationWithAddress(
        HashIdPreimageSorobanAuthorizationWithAddress {
            network_id,
            nonce,
            signature_expiration_ledger,
            address,
            invocation,
        },
    )
}

/// Recomputes one vector's preimage and payload and compares them to the record.
///
/// `path` is the vector's JSON file. A case with no recorded preimage comes back
/// as a `Skip`, and a genuine disagreement as a `Mismatch`; neither is an error.
/// An error means the file could not be read or decoded at all.
pub fn check_vector(path: &Path) -> Result<CaseResult, String> {
    let text = fs::read_to_string(path).map_err(|error| format!("reading {}: {error}", path.display()))?;
    let vector: Value =
        serde_json::from_str(&text).map_err(|error| format!("parsing {}: {error}", path.display()))?;

    let name = vector
        .get("name")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| {
            path.file_name()
                .map_or_else(|| path.display().to_string(), |name| name.to_string_lossy().into_owned())
        });

    let entry_xdr = vector
        .get("unsigned_entry_xdr")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{name}: unsigned_entry_xdr is missing or not a string"))?;
    let entry = SorobanAuthorizationEntry::from_xdr_base64(entry_xdr, Limits::none())
        .map_err(|error| format!("{name}: decoding unsigned_entry_xdr: {error}"))?;

    let credential_type = credential_type_name(&entry.credentials);
    let want_preimage = vector.get("preimage_xdr").and_then(Value::as_str).unwrap_or("");

    if want_preimage.is_empty() {
        return Ok(CaseResult {
            name,
            status: Status::Skip,
            detail: format!(
                "no recorded preimage: credential_type={credential_type}; \
                 cases with no preimage cannot be recomputed"
            ),
        });
    }

    let valid_until_ledger = vector
        .get("valid_until_ledger")
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{name}: valid_until_ledger is missing or not an integer"))?;
    let valid_until_ledger = u32::try_from(valid_until_ledger)
        .map_err(|_| format!("{name}: valid_until_ledger does not fit in u32"))?;
    let network_passphrase = vector
        .get("network_passphrase")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{name}: network_passphrase is missing or not a string"))?;

    let preimage = build_preimage(&entry, valid_until_ledger, network_passphrase)?;
    let got_preimage = preimage
        .to_xdr_base64(Limits::none())
        .map_err(|error| format!("{name}: marshalling the preimage: {error}"))?;
    let preimage_bytes = preimage
        .to_xdr(Limits::none())
        .map_err(|error| format!("{name}: marshalling the preimage bytes: {error}"))?;
    let got_payload = hex::encode(sha256(&preimage_bytes));
    let want_payload = vector
        .get("payload_hex")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();

    let mut problems = Vec::new();
    if got_preimage != want_preimage {
        problems.push(format!(
            "preimage differs\n    want {want_preimage}\n     got {got_preimage}"
        ));
    }
    if got_payload != want_payload {
        problems.push(format!(
            "payload differs\n    want {want_payload}\n     got {got_payload}"
        ));
    }

    if problems.is_empty() {
        Ok(CaseResult { name, status: Status::Match, detail: String::new() })
    } else {
        Ok(CaseResult { name, status: Status::Mismatch, detail: problems.join("; ") })
    }
}

/// Checks every `*.json` vector in `vectors_dir`, in name order.
///
/// An empty directory is an error rather than an empty result: a harness that
/// silently found nothing to check would report success by doing nothing.
pub fn run(vectors_dir: &Path) -> Result<Vec<CaseResult>, String> {
    let mut paths: BTreeMap<String, PathBuf> = BTreeMap::new();
    let entries = fs::read_dir(vectors_dir)
        .map_err(|error| format!("reading {}: {error}", vectors_dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("reading {}: {error}", vectors_dir.display()))?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
            paths.insert(entry.file_name().to_string_lossy().into_owned(), path);
        }
    }
    if paths.is_empty() {
        return Err(format!(
            "no vectors found in {}; run `cd testdata/gen && npm ci && node gen.mjs` to generate them",
            vectors_dir.display()
        ));
    }

    paths.values().map(|path| check_vector(path)).collect()
}

/// Prints a human-readable report and returns the process exit code.
pub fn report<O: Write, E: Write>(
    results: &[CaseResult],
    out: &mut O,
    err: &mut E,
) -> i32 {
    let matched = results.iter().filter(|result| result.is_match()).count();
    let mismatched = results.iter().filter(|result| result.is_mismatch()).count();
    let skipped = results.iter().filter(|result| result.is_skip()).count();

    for result in results {
        match result.status {
            Status::Match => {
                let _ = writeln!(out, "  ok    {}", result.name);
            }
            // Skips go to stderr so they cannot be mistaken for "ok" lines.
            Status::Skip => {
                let _ = writeln!(err, "  skip  {}: {}", result.name, result.detail);
            }
            Status::Mismatch => {}
        }
    }
    for result in results.iter().filter(|result| result.is_mismatch()) {
        let _ = writeln!(err, "  FAIL  {}: {}", result.name, result.detail);
    }

    let _ = writeln!(
        out,
        "\nparity harness: {matched} matched, {skipped} skipped, {mismatched} mismatched (of {})",
        results.len()
    );

    if mismatched > 0 {
        let _ = writeln!(
            err,
            "\nDo not edit a vector to make this pass. A disagreement here means one of the \
             two implementations is wrong; open an issue with the protocol reference \
             (CAP-46-11, CAP-71-01, CAP-71-02) and investigate."
        );
        return 1;
    }
    // A run that checked nothing is not a pass.
    if matched == 0 {
        let _ = writeln!(
            err,
            "parity harness: nothing was actually checked; refusing to report success"
        );
        return 1;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// The committed vectors directory, resolved from the crate root.
    fn vectors_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../vectors")
    }

    fn temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before the epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "soroauth-parity-rust-{}-{label}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("creating a temp dir");
        dir
    }

    /// Copies one committed vector into a fresh temp dir, mutating the JSON.
    fn copy_vector(name: &str, mutate: impl FnOnce(&mut Value)) -> (PathBuf, PathBuf) {
        let dir = temp_dir(name);
        let source = vectors_dir().join(name);
        let mut doc: Value =
            serde_json::from_str(&fs::read_to_string(&source).expect("reading the vector"))
                .expect("parsing the vector");
        mutate(&mut doc);
        let target = dir.join(name);
        fs::write(&target, serde_json::to_string(&doc).expect("serialising the vector"))
            .expect("writing the tampered vector");
        (dir, target)
    }

    #[test]
    fn every_committed_vector_matches_or_skips() {
        let results = run(&vectors_dir()).expect("running the harness");
        let mismatched: Vec<&str> =
            results.iter().filter(|r| r.is_mismatch()).map(|r| r.name.as_str()).collect();
        assert!(mismatched.is_empty(), "vectors disagreed with Rust stellar-xdr: {mismatched:?}");
        let matched = results.iter().filter(|r| r.is_match()).count();
        assert!(
            matched >= 11,
            "expected at least the 11 address-arm vectors to be checked, got {matched}"
        );
    }

    #[test]
    fn source_account_vectors_skip_loudly() {
        for name in ["source_account_testnet.json", "source_account_public.json"] {
            let result = check_vector(&vectors_dir().join(name)).expect("checking");
            assert!(result.is_skip(), "{name} should skip, got {:?}", result.status);
            assert!(result.detail.contains("source_account"), "{}", result.detail);
        }
    }

    #[test]
    fn a_tampered_payload_is_detected() {
        // The negative control: if the harness cannot see a changed payload, it
        // cannot see a real disagreement either.
        let (dir, path) =
            copy_vector("v2_single_testnet.json", |doc| doc["payload_hex"] = Value::from("00".repeat(32)));
        let result = check_vector(&path).expect("checking the tampered vector");
        fs::remove_dir_all(&dir).ok();
        assert!(result.is_mismatch(), "{result:?}");
        assert!(result.detail.contains("payload differs"), "{}", result.detail);
    }

    #[test]
    fn a_tampered_preimage_is_detected() {
        let (dir, path) =
            copy_vector("legacy_single_testnet.json", |doc| doc["preimage_xdr"] = Value::from("AAAA"));
        let result = check_vector(&path).expect("checking the tampered vector");
        fs::remove_dir_all(&dir).ok();
        assert!(result.is_mismatch(), "{result:?}");
        assert!(result.detail.contains("preimage differs"), "{}", result.detail);
    }

    #[test]
    fn checking_does_not_modify_the_vector_file() {
        let (dir, path) = copy_vector("v2_sub_invocations.json", |_| {});
        let before = fs::read(&path).expect("reading before");
        check_vector(&path).expect("checking");
        let after = fs::read(&path).expect("reading after");
        fs::remove_dir_all(&dir).ok();
        assert_eq!(before, after, "the harness wrote to a vector");
    }

    #[test]
    fn a_vacuous_run_is_a_failure() {
        let results = vec![CaseResult {
            name: "x".to_string(),
            status: Status::Skip,
            detail: "reason".to_string(),
        }];
        let code = report(&results, &mut Vec::new(), &mut Vec::new());
        assert_eq!(code, 1);
    }

    #[test]
    fn all_matched_succeeds() {
        let results = vec![
            CaseResult { name: "a".to_string(), status: Status::Match, detail: String::new() },
            CaseResult { name: "b".to_string(), status: Status::Match, detail: String::new() },
        ];
        let code = report(&results, &mut Vec::new(), &mut Vec::new());
        assert_eq!(code, 0);
    }

    #[test]
    fn a_mismatch_fails_and_names_the_case() {
        let results = vec![
            CaseResult { name: "good".to_string(), status: Status::Match, detail: String::new() },
            CaseResult {
                name: "bad".to_string(),
                status: Status::Mismatch,
                detail: "payload differs".to_string(),
            },
        ];
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = report(&results, &mut out, &mut err);
        let err = String::from_utf8(err).expect("utf-8");
        assert_eq!(code, 1);
        assert!(err.contains("bad"));
        assert!(err.contains("payload differs"));
    }

    #[test]
    fn the_build_is_pinned_to_the_expected_stellar_xdr() {
        assert_eq!(STELLAR_XDR_VERSION, REQUIRED_STELLAR_XDR_VERSION);
        require_pinned().expect("the pinned check");
    }
}
