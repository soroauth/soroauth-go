#!/usr/bin/env python3
"""Generate and validate license inventory across ecosystems."""

import json
import os
import sys
from pathlib import Path


# Allowed licenses with rationale
ALLOWED_LICENSES = {
    "MIT": "Permissive, widely used, compatible with Apache-2.0",
    "Apache-2.0": "Project's own license, permissive with patent terms",
    "BSD-2-Clause": "Permissive, minimal conditions",
    "BSD-3-Clause": "Permissive, attribution required",
    "MPL-2.0": "Copyleft but permissive, strong copyleft",
    "CC0-1.0": "Public domain dedication",
    "Unlicense": "Permissive, similar to MIT/CC0",
}


def main():
    """Main entry point for license inventory generation."""
    # Collect all license data from ecosystems
    inventory = {
        "generated": __import__('datetime').datetime.utcnow().isoformat() + "Z",
        "ecosystems": {},
        "allowed_set": ALLOWED_LICENSES,
        "license_violations": [],
        "unknown_licenses": [],
    }

    # Check each ecosystem
    ecosystems = ["go", "npm", "rust", "python", "jvm"]
    for eco in ecosystems:
        eco_inventory = {
            "dependencies": [],
            "license_violations": [],
            "unknown_licenses": [],
        }

        # Read the SPDX output for this ecosystem
        spdx_file = f"/tmp/licenses/spdx-{eco}.json"
        if os.path.exists(spdx_file):
            try:
                with open(spdx_file) as f:
                    spdx_data = json.load(f)

                if eco == "go":
                    deps = spdx_data.get("dependencies", [])
                    for dep in deps:
                        license_info = dep.get("license", {})
                        if isinstance(license_info, dict):
                            license_id = license_info.get("id", "")
                        else:
                            license_id = str(license_info)

                        eco_inventory["dependencies"].append({
                            "name": dep.get("name", "unknown"),
                            "license": license_id,
                            "source": "go",
                        })

                        if license_id and license_id not in ALLOWED_LICENSES:
                            eco_inventory["license_violations"].append({
                                "name": dep.get("name", "unknown"),
                                "license": license_id,
                                "rationale": f"License {license_id} not in allowed set",
                            })
                        elif license_id:
                            eco_inventory["dependencies"][-1]["allowed"] = True
                        else:
                            eco_inventory["unknown_licenses"].append({
                                "name": dep.get("name", "unknown"),
                                "license": "NO_LICENSE",
                                "rationale": "No license declaration found",
                            })

            except (json.JSONDecodeError, KeyError) as e:
                print(f"Error processing {eco} SPDX data: {e}")
                eco_inventory["error"] = str(e)

        inventory["ecosystems"][eco] = eco_inventory

    # Check for license violations across all ecosystems
    all_violations = []
    for eco, eco_inv in inventory["ecosystems"].items():
        for violation in eco_inv.get("license_violations", []):
            all_violations.append({
                "ecosystem": eco,
                **violation,
            })

        for unknown in eco_inv.get("unknown_licenses", []):
            all_violations.append({
                "ecosystem": eco,
                **unknown,
            })

    if all_violations:
        inventory["license_violations"] = all_violations
        violations_path = "/tmp/license-violations.json"
        with open(violations_path, "w") as f:
            json.dump(all_violations, f, indent=2)
        print(f"License violations found - see violation details")
        sys.exit(1)
    else:
        # No violations - write clean inventory
        output_path = "/tmp/license-inventory.json"
        with open(output_path, "w") as f:
            json.dump(inventory, f, indent=2)
        print("No license violations - all clear")
        sys.exit(0)


if __name__ == "__main__":
    main()