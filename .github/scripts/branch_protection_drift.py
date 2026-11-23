#!/usr/bin/env python3
"""Compare live vs committed branch protection configuration and report drift."""

import json
import sys
import os


def main():
    """Main entry point for branch protection drift detection."""
    # Read live branch protection from GitHub API
    live_str = os.environ.get("LIVE_PROTECTION_JSON", "")
    committed_str = os.environ.get("COMMITTED_PROTECTION_JSON", "")

    if not live_str or not committed_str:
        print("Missing environment variables")
        sys.exit(1)

    try:
        live = json.loads(live_str)
    except json.JSONDecodeError:
        print("Failed to parse live protection JSON")
        sys.exit(1)

    try:
        committed = json.loads(committed_str)
    except json.JSONDecodeError:
        print("Failed to parse committed protection JSON")
        sys.exit(1)

    # Compare key fields
    differences = []

    # required_approvals
    if live.get("required_approvals") != committed.get("required_approvals"):
        differences.append(f"required_approvals: live={live.get('required_approvals')} committed={committed.get('required_approvals')}")

    # require_code_owner_reviews
    if live.get("require_code_owner_reviews") != committed.get("require_code_owner_reviews"):
        differences.append(f"require_code_owner_reviews: live={live.get('require_code_owner_reviews')} committed={committed.get('require_code_owner_reviews')}")

    # dismiss_stale_reviews
    if live.get("dismiss_stale_reviews") != committed.get("dismiss_stale_reviews"):
        differences.append(f"dismiss_stale_reviews: live={live.get('dismiss_stale_reviews')} committed={committed.get('dismiss_stale_reviews')}")

    # require_last_push_author_review
    if live.get("require_last_push_author_review") != committed.get("require_last_push_author_review"):
        differences.append(f"require_last_push_author_review: live={live.get('require_last_push_author_review')} committed={committed.get('require_last_push_author_review')}")

    # enforce_admins
    if live.get("enforce_admins") != committed.get("enforce_admins"):
        differences.append(f"enforce_admins: live={live.get('enforce_admins')} committed={committed.get('enforce_admins')}")

    # prevent_draft_merge
    if live.get("prevent_draft_merge") != committed.get("prevent_draft_merge"):
        differences.append(f"prevent_draft_merge: live={live.get('prevent_draft_merge')} committed={committed.get('prevent_draft_merge')}")

    # merge_method
    if live.get("merge_method") != committed.get("merge_method"):
        differences.append(f"merge_method: live={live.get('merge_method')} committed={committed.get('merge_method')}")

    # default_merge_method
    if live.get("default_merge_method") != committed.get("default_merge_method"):
        differences.append(f"default_merge_method: live={live.get('default_merge_method')} committed={committed.get('default_merge_method')}")

    # require_linear_history
    if live.get("require_linear_history") != committed.get("require_linear_history"):
        differences.append(f"require_linear_history: live={live.get('require_linear_history')} committed={committed.get('require_linear_history')}")

    # require_status_checks
    if live.get("require_status_checks") != committed.get("require_status_checks"):
        differences.append(f"require_status_checks: live={live.get('require_status_checks')} committed={committed.get('require_status_checks')}")

    # status_checks.strict
    if live.get("status_checks", {}).get("strict") != committed.get("status_checks", {}).get("strict"):
        differences.append(f"status_checks.strict: live={live.get('status_checks', {}).get('strict')} committed={committed.get('status_checks', {}).get('strict')}")

    # status_checks.contexts
    live_ctxs = sorted(live.get("status_checks", {}).get("contexts", []))
    committed_ctxs = sorted(committed.get("status_checks", {}).get("contexts", []))
    if live_ctxs != committed_ctxs:
        differences.append(f"status_checks.contexts: live={live_ctxs} committed={committed_ctxs}")

    # bypass_actors
    live_bypass = live.get("bypass_actors", {})
    committed_bypass = committed.get("bypass_actors", {})

    # Compare users
    live_users = sorted(live_bypass.get("users", []))
    committed_users = sorted(committed_bypass.get("users", []))
    if live_users != committed_users:
        differences.append(f"bypass_actors.users: live={live_users} committed={committed_users}")

    # Compare teams
    live_teams = sorted(live_bypass.get("teams", []))
    committed_teams = sorted(committed_bypass.get("teams", []))
    if live_teams != committed_teams:
        differences.append(f"bypass_actors.teams: live={live_teams} committed={committed_teams}")

    # Compare apps
    live_apps = sorted(live_bypass.get("apps", []))
    committed_apps = sorted(committed_bypass.get("apps", []))
    if live_apps != committed_apps:
        differences.append(f"bypass_actors.apps: live={live_apps} committed={committed_apps}")

    if differences:
        print("DRIFT_DETECTED=true")
        # Write detailed diff
        with open("/github/workspace/.github/drift-report.md", "w") as f:
            f.write("# Branch Protection Drift Detected\n\n")
            f.write(f"Found {len(differences)} differences between live and committed branch protection configuration.\n\n")
            f.write("## Differences\n")
            for d in differences:
                f.write(f"- {d}\n")
            f.write("\n---\n")
            f.write("## Committed Configuration\n```json\n")
            json.dump(committed, f, indent=2)
            f.write("\n```\n")
            f.write("## Live Configuration\n```json\n")
            json.dump(live, f, indent=2)
            f.write("\n```\n")
    else:
        print("NO_DRIFT_DETECTED=true")


if __name__ == "__main__":
    main()