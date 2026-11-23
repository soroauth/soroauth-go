#!/usr/bin/env python3
"""Report findings from advisory scanning and fail the build if needed."""

import json
import os
import subprocess
import sys
from pathlib import Path


def run_osv_scanner(targets):
    """Run osv-scanner against the given targets."""
    cmd = ["osv-scanner"] + targets
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0 and result.stdout.strip():
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                return {"raw": result.stdout[:1000], "error": result.stderr[:500]}
        return []
    except FileNotFoundError:
        return {"error": "osv-scanner not found"}


def main():
    """Main entry point for advisory scanning report."""
    # Collect all scanner results
    ecosystems = {
        'go': ['./go.mod', './go.sum'],
        'npm': ['package-lock.json'],
        'rust': ['Cargo.lock'],
        'python': ['pyproject.toml', 'setup.py'],
        'jvm': ['pom.xml'],
    }

    all_findings = []
    scanner_failed = False

    for ecosystem, targets in ecosystems.items():
        # Filter to existing targets
        existing_targets = [t for t in targets if os.path.exists(t)]
        if not existing_targets:
            print(f"No {ecosystem} lockfiles found, skipping")
            continue

        # Run osv-scanner
        findings = run_osv_scanner(existing_targets)
        
        if isinstance(findings, dict) and findings.get("error"):
            print(f"osv-scanner failed for {ecosystem}: {findings['error']}")
            scanner_failed = True
            all_findings.append({
                "ecosystem": ecosystem,
                "error": findings["error"]
            })
        elif isinstance(findings, list):
            for f in findings:
                f["ecosystem"] = ecosystem
            all_findings.extend(findings)
        else:
            print(f"Unexpected format for {ecosystem}")
            scanner_failed = True

    # Write findings to file
    output_path = Path("/tmp/advisory-scan-results.json")
    with open(output_path, "w") as f:
        json.dump(all_findings, f, indent=2)

    # Fail the build if scanner itself failed
    if scanner_failed:
        print("::error ::Advisory scanner failed - see results")
        sys.exit(1)

    # Check if there are any findings
    if all_findings:
        print(f"Found {len(all_findings)} vulnerability findings across ecosystems")
        for f in all_findings:
            eco = f.get("ecosystem", "unknown")
            pkg = f.get("package", {}).get("name", "unknown")
            version = f.get("package", {}).get("version", "unknown")
            severity = f.get("severity", "unknown")
            print(f"  [{eco}] {pkg} {version} - {severity}")
        # Exit 1 to fail the build if findings exist
        sys.exit(1)
    else:
        print("No vulnerability findings - all clear")
        sys.exit(0)


if __name__ == "__main__":
    main()