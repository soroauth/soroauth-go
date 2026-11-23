#!/usr/bin/env python3
"""Create gitleaks allowlist for deterministic test keys."""

import os

# The test keys are derived from sha256(labels), so we allowlist by derivation
# rather than by pattern. The labels are public and their keys are
# deterministically derived, so they will never be "real" secrets.

allowlist = """[[rules]]
  rule = "allowlist"
  # Deterministic test keys derived from sha256(label) are allowed
  # Labels used: sorauth-vector-signer-1 through sorauth-vector-signer-10
  allow = [
    "soroauth-vector-signer-1",
    "soroauth-vector-signer-2",
    "soroauth-vector-signer-3",
    "soroauth-vector-signer-4",
    "soroauth-vector-signer-5",
    "soroauth-vector-signer-6",
    "soroauth-vector-signer-7",
    "soroauth-vector-signer-8",
    "soroauth-vector-signer-9",
    "soroauth-vector-signer-10",
  ]
  comment = "Deterministic test keys derived from sha256(label) - public labels, not secret patterns"
"""

output_path = "/tmp/gitleaks_allowlist.toml"
with open(output_path, "w") as f:
    f.write(allowlist)

print(f"Allowlist written to {output_path}")