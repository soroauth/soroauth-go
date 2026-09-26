#!/usr/bin/env python3
"""Unit tests for the Python parity harness.

Standard library only (`unittest`), so running these needs no extra install
beyond the pinned reference SDK the harness itself needs. Tests that require
that SDK skip cleanly when it is absent; tests about *how* a mismatch or a skip
is reported do not need it.

Run with:

    python3 testdata/parity-python/test_parity.py
"""

from __future__ import annotations

import io
import json
import shutil
import sys
import tempfile
import unittest
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as installed_version
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import parity  # noqa: E402


def sdk_is_pinned() -> bool:
    """Whether the exact pinned reference SDK is installed."""
    try:
        return installed_version("stellar-sdk") == parity.REQUIRED_SDK_VERSION
    except PackageNotFoundError:
        return False


needs_sdk = unittest.skipUnless(
    sdk_is_pinned(),
    f"stellar-sdk=={parity.REQUIRED_SDK_VERSION} is not installed",
)


def copy_vector(name: str, mutate) -> tempfile.TemporaryDirectory:
    """Copy one committed vector into a fresh temp dir, mutating the JSON.

    ``mutate`` receives the decoded vector dict and may change it in place. The
    returned TemporaryDirectory must be kept alive by the caller.
    """
    src = parity.DEFAULT_VECTORS_DIR / name
    doc = json.loads(src.read_text(encoding="utf-8"))
    mutate(doc)

    tmp = tempfile.TemporaryDirectory()
    (Path(tmp.name) / name).write_text(json.dumps(doc), encoding="utf-8")
    return tmp


class ReportTests(unittest.TestCase):
    """The reporting and exit-code contract, which needs no SDK."""

    def test_vacuous_run_is_a_failure(self):
        # A run where every case was skipped checked nothing, so it must not
        # report success: otherwise the harness could rot into a no-op.
        code = parity.report(
            [parity.CaseResult("x", "skip", "reason")],
            out=io.StringIO(),
            err=io.StringIO(),
        )
        self.assertEqual(code, 1)

    def test_skip_is_reported_on_stderr_not_stdout(self):
        out, err = io.StringIO(), io.StringIO()
        parity.report(
            [
                parity.CaseResult("good", "match"),
                parity.CaseResult("skipped", "skip", "no preimage"),
            ],
            out=out,
            err=err,
        )
        self.assertIn("ok    good", out.getvalue())
        # The per-case skip line is on stderr, not among the "ok" lines.
        self.assertNotIn("skip  skipped", out.getvalue())
        self.assertIn("skip  skipped: no preimage", err.getvalue())
        # The summary (which counts skips) is fine on stdout.
        self.assertIn("1 skipped", out.getvalue())

    def test_mismatch_fails_and_names_the_case(self):
        err = io.StringIO()
        code = parity.report(
            [
                parity.CaseResult("good", "match"),
                parity.CaseResult("bad", "mismatch", "payload differs"),
            ],
            out=io.StringIO(),
            err=err,
        )
        self.assertEqual(code, 1)
        self.assertIn("bad", err.getvalue())
        self.assertIn("payload differs", err.getvalue())

    def test_all_matched_succeeds(self):
        code = parity.report(
            [parity.CaseResult("a", "match"), parity.CaseResult("b", "match")],
            out=io.StringIO(),
            err=io.StringIO(),
        )
        self.assertEqual(code, 0)

    def test_empty_vector_directory_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit):
                parity.run(Path(tmp))


@needs_sdk
class VectorTests(unittest.TestCase):
    """Tests that exercise the real pinned SDK against the real vectors."""

    def test_every_committed_vector_matches_or_skips(self):
        results = parity.run(parity.DEFAULT_VECTORS_DIR)
        mismatched = [r.name for r in results if r.mismatched]
        self.assertEqual(mismatched, [], f"vectors disagreed with Python: {mismatched}")
        # Completeness: the address arms must actually be checked, not skipped.
        self.assertGreaterEqual(
            len([r for r in results if r.matched]),
            11,
            "expected at least the 11 address-arm vectors to be checked",
        )

    def test_source_account_vectors_skip_loudly(self):
        for name in ("source_account_testnet.json", "source_account_public.json"):
            with self.subTest(vector=name):
                result = parity.check_vector(parity.DEFAULT_VECTORS_DIR / name)
                self.assertTrue(result.skipped, f"{name} should skip, got {result.status}")
                self.assertIn("source_account", result.detail)

    def test_a_tampered_payload_is_detected(self):
        # The negative control: if the harness cannot tell that a recorded
        # payload was changed, it cannot tell that a real disagreement exists.
        tmp = copy_vector(
            "v2_single_testnet.json",
            lambda doc: doc.__setitem__("payload_hex", "00" * 32),
        )
        try:
            result = parity.check_vector(Path(tmp.name) / "v2_single_testnet.json")
            self.assertTrue(result.mismatched, result)
            self.assertIn("payload differs", result.detail)
        finally:
            tmp.cleanup()

    def test_a_tampered_preimage_is_detected(self):
        tmp = copy_vector(
            "legacy_single_testnet.json",
            lambda doc: doc.__setitem__("preimage_xdr", "AAAA"),
        )
        try:
            result = parity.check_vector(Path(tmp.name) / "legacy_single_testnet.json")
            self.assertTrue(result.mismatched, result)
            self.assertIn("preimage differs", result.detail)
        finally:
            tmp.cleanup()

    def test_checking_does_not_modify_the_vector_file(self):
        # The harness must never write to a vector. Compare bytes around a check.
        tmp = copy_vector("v2_sub_invocations.json", lambda doc: None)
        try:
            path = Path(tmp.name) / "v2_sub_invocations.json"
            before = path.read_bytes()
            parity.check_vector(path)
            self.assertEqual(path.read_bytes(), before)
        finally:
            tmp.cleanup()

    def test_run_over_a_temp_dir_of_copies(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("legacy_single_testnet.json", "v2_create_contract.json"):
                shutil.copy(parity.DEFAULT_VECTORS_DIR / name, Path(tmp) / name)
            results = parity.run(Path(tmp))
            self.assertTrue(all(r.matched for r in results), results)


if __name__ == "__main__":
    unittest.main(verbosity=2)
