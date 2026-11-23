#!/usr/bin/env python3
"""Check gitleaks scan results and fail if non-allowlisted secrets found."""

import json
import os
import sys


def main():
    """Check for non-allowlisted secrets and exit with error if found."""
    if os.path.exists('/tmp/sarif-results.json'):
        with open('/tmp/sarif-results.json') as f:
            data = json.load(f)
        results = data.get('runs', [{}])[0].get('results', [])
        # Filter out allowlisted findings
        allowlisted = {'soroauth-vector-signer-1', 'soroauth-vector-signer-2', 'soroauth-vector-signer-3',
                       'soroauth-vector-signer-4', 'soroauth-vector-signer-5', 'soroauth-vector-signer-6',
                       'soroauth-vector-signer-7', 'soroauth-vector-signer-8', 'soroauth-vector-signer-9',
                       'soroauth-vector-signer-10'}
        non_allowlisted = [r for r in results if r.get('ruleId') not in allowlisted]
        if non_allowlisted:
            print(f'Found {len(non_allowlisted)} non-allowlisted secret findings')
            for r in non_allowlisted:
                print(f'  - {r.get("ruleId")}: {r.get("message", {}).get("text", "")}')
            sys.exit(1)
        else:
            print('No non-allowlisted secrets found - all clear')
    else:
        print('No SARIF results found')


if __name__ == "__main__":
    main()