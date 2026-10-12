#!/usr/bin/env python3
"""Create and maintain a Drips Wave issue backlog on GitHub.

A backlog JSON file is the source of truth; issue bodies are rendered from it,
so the published issues cannot drift from the document they were reviewed as.

Dry run by default: prints everything it would do and changes nothing.

    ./scripts/wave_issues.py --backlog docs/WAVE10_BACKLOG.json
    ./scripts/wave_issues.py --backlog docs/WAVE10_BACKLOG.json --apply
    ./scripts/wave_issues.py --backlog docs/WAVE10_BACKLOG.json --apply --limit 5

This supersedes scripts/wave9_issues.py, which hard-coded Wave 9's file names.
Unlike that script, this one reads every existing issue title first and skips
any backlog entry whose title already exists, because `gh issue create` is not
idempotent and a second run would otherwise duplicate the whole backlog. Pass
--allow-duplicate-titles only if you genuinely intend two issues with one title.
"""
import argparse
import collections
import json
import os
import subprocess
import sys

REPO = "soroauth/soroauth-go"
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

POINTS = {"high": 200, "medium": 150, "trivial": 100}
DRIPS_NAME = {"high": "High", "medium": "Medium", "trivial": "Trivial"}

LABELS = [
    ("complexity:trivial", "c2e0c6", "Trivial — 100 points. Small, self-contained."),
    ("complexity:medium", "fbca04", "Medium — 150 points. Standard feature or involved fix."),
    ("complexity:high", "d93f0b", "High — 200 points. New subsystem, integration or refactor."),
    ("area:signers", "1d76db", "Signer implementations and the Signer interface"),
    ("area:testing", "5319e7", "Golden vectors, fuzzing, parity, benchmarks, e2e"),
    ("area:api", "0e8a16", "Exported library API"),
    ("area:docs", "006b75", "Documentation and guides"),
    ("area:tooling", "bfd4f2", "CLI, CI, scripts, release automation"),
    ("area:integrations", "d4c5f9", "WASM, browser, wallets, RPC, fixture contracts"),
    ("area:protocol", "e99695", "CAP support and protocol compatibility"),
    ("good first issue", "7057ff", "Trivial and needs no Soroban context; a newcomer's first PR"),
]

BEFORE_YOU_START = """## 📚 Before You Start
- Read [CONTRIBUTING.md](https://github.com/{repo}/blob/main/CONTRIBUTING.md) for local setup, commit format, and the PR checklist.
- Skim [ARCHITECTURE.md](https://github.com/{repo}/blob/main/ARCHITECTURE.md) for the signing flow, the package map, and the delegate model.
- Anything that changes the bytes soroauth emits must cite the CAP that requires it and ship a golden vector. Never edit a vector by hand."""

ADDITIONAL = """## 📋 Additional Notes
**Complexity: {level} ({points} points)**

- **Get assigned first.** Comment *I'd like to work on this* and wait for assignment. Unassigned PRs may duplicate someone else's work.
- **48-hour progress rule.** You have 48 hours from assignment to show meaningful progress: a draft PR, a status update on the issue, or a question. Issues that go silent for 48h may be reassigned to keep the Wave moving. If you need more time, just say so on the issue.
- **PR description must link this issue** with `Closes #`, describe what you changed, and state how you verified it.
- **Keep the PR to this issue's scope.** Unrelated fixes you spot along the way are welcome as separate issues or PRs.
- **CI must be green** before requesting review. `main` requires a pull request and both status checks.
- **If the work turns out materially larger** than the assigned complexity once you're in the code, say so on the issue rather than absorbing it silently."""


def render(issue):
    parts = ["## 📘 Description", issue["description"]]
    if issue.get("why"):
        parts += ["", "**Why this matters:** " + issue["why"]]
    if issue.get("good_first_issue"):
        parts += ["", "**Good first issue.** Entry point: `%s`."
                  % issue.get("entry_point", "see the acceptance criteria")]
    parts += ["", "## ✅ Acceptance Criteria"]
    parts += ["- [ ] " + c for c in issue["criteria"]]
    parts += ["", "## 🔧 Implementation Guidance"]
    parts += ["- " + g for g in issue["guidance"]]
    parts += ["", BEFORE_YOU_START.format(repo=REPO), "",
              ADDITIONAL.format(level=DRIPS_NAME[issue["complexity"]],
                                points=POINTS[issue["complexity"]])]
    return "\n".join(parts)


def markdown(backlog, source):
    """Render the backlog as a review document.

    Generated, never hand-edited: the JSON is the source of truth, and a
    second hand-maintained copy would drift from the issues that get created.
    """
    by_complexity = collections.Counter(i["complexity"] for i in backlog)
    total = sum(POINTS[i["complexity"]] for i in backlog)

    lines = [
        "# Wave 10 issue backlog",
        "",
        "<!-- Generated from %s by scripts/wave_issues.py --markdown. Do not edit by hand. -->" % source,
        "",
        "%d issues, %d points. `%s` is the source of truth; this document exists so the"
        % (len(backlog), total, source),
        "backlog can be read and reviewed before any issue is created.",
        "",
        "| Complexity | Issues | Points each | Points |",
        "| ---------- | -----: | ----------: | -----: |",
    ]
    for level in ("high", "medium", "trivial"):
        n = by_complexity[level]
        lines.append("| %s | %d | %d | %d |" % (DRIPS_NAME[level], n, POINTS[level], n * POINTS[level]))
    lines += ["| **Total** | **%d** | | **%d** |" % (len(backlog), total), ""]

    areas = collections.Counter(i["area"] for i in backlog)
    lines += ["| Area | Issues |", "| ---- | -----: |"]
    for area, n in sorted(areas.items()):
        lines.append("| `%s` | %d |" % (area, n))
    lines += [""]

    for level in ("high", "medium", "trivial"):
        group = [i for i in backlog if i["complexity"] == level]
        lines += ["## %s — %d points each (%d issues)" % (DRIPS_NAME[level], POINTS[level], len(group)), ""]
        for area in sorted({i["area"] for i in group}):
            lines += ["### `%s`" % area, ""]
            for issue in [i for i in group if i["area"] == area]:
                lines.append("#### %s" % issue["title"])
                lines += ["", issue["description"]]
                if issue.get("why"):
                    lines += ["", "**Why this matters:** " + issue["why"]]
                if issue.get("good_first_issue"):
                    lines += ["", "**Good first issue.** Entry point: `%s`."
                              % issue.get("entry_point", "see the acceptance criteria")]
                lines += ["", "*Acceptance criteria*", ""]
                lines += ["- " + c for c in issue["criteria"]]
                lines += ["", "*Implementation guidance*", ""]
                lines += ["- " + g for g in issue["guidance"]]
                lines += [""]
    return "\n".join(lines) + "\n"


def validate(backlog):
    """Refuse a malformed backlog before touching GitHub.

    Every check here is one that would otherwise produce a published issue
    nobody can act on, or a points total that disagrees with the submission.
    """
    required = {"title", "complexity", "area", "description", "criteria", "guidance"}
    problems = []
    seen = collections.Counter(i.get("title", "") for i in backlog)
    for n, issue in enumerate(backlog, 1):
        where = issue.get("title") or ("entry %d" % n)
        missing = required - set(issue)
        if missing:
            problems.append("%s: missing %s" % (where, ", ".join(sorted(missing))))
            continue
        if issue["complexity"] not in POINTS:
            problems.append("%s: unknown complexity %r" % (where, issue["complexity"]))
        if seen[issue["title"]] > 1:
            problems.append("%s: duplicate title within the backlog" % where)
        if not issue["criteria"]:
            problems.append("%s: no acceptance criteria" % where)
        if not issue["guidance"]:
            problems.append("%s: no implementation guidance" % where)
        if issue.get("good_first_issue") and issue["complexity"] != "trivial":
            problems.append("%s: good first issue but not trivial" % where)
    return problems


def gh(*args, capture=True):
    return subprocess.run(["gh", *args], check=True,
                          capture_output=capture, text=True).stdout


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--backlog", required=True,
                   help="path to the backlog JSON (e.g. docs/WAVE10_BACKLOG.json)")
    p.add_argument("--apply", action="store_true", help="actually create the issues")
    p.add_argument("--limit", type=int, default=0,
                   help="only show/create the first N issues")
    p.add_argument("--skip-labels", action="store_true",
                   help="do not create or update labels")
    p.add_argument("--allow-duplicate-titles", action="store_true",
                   help="create an issue even when one with the same title exists")
    p.add_argument("--bodies", action="store_true",
                   help="print every rendered body in the dry run (verbose)")
    p.add_argument("--markdown", metavar="PATH",
                   help="write a human-readable review document and exit, touching GitHub not at all")
    args = p.parse_args()

    path = args.backlog if os.path.isabs(args.backlog) else os.path.join(ROOT, args.backlog)
    backlog = json.load(open(path))

    problems = validate(backlog)
    if problems:
        print("backlog is not valid; nothing was done:\n", file=sys.stderr)
        for problem in problems:
            print("  " + problem, file=sys.stderr)
        return 1

    for issue in backlog:
        if not issue["area"].startswith("area:"):
            issue["area"] = "area:" + issue["area"]

    if args.markdown:
        out = args.markdown if os.path.isabs(args.markdown) else os.path.join(ROOT, args.markdown)
        with open(out, "w") as fh:
            fh.write(markdown(backlog, os.path.relpath(path, ROOT)))
        print("wrote %s (%d issues)" % (out, len(backlog)))
        return 0

    # ---- labels ----
    if not args.skip_labels:
        print("== labels ==")
        for name, color, desc in LABELS:
            if args.apply:
                gh("label", "create", name, "--repo", REPO, "--color", color,
                   "--description", desc, "--force")
                print("  ensured %s" % name)
            else:
                print("  would ensure %-22s #%s  %s" % (name, color, desc))
        print()

    # ---- existing titles, so a re-run cannot duplicate the backlog ----
    live = json.loads(gh("issue", "list", "--repo", REPO, "--state", "all",
                         "--limit", "1000", "--json", "number,title"))
    by_title = {x["title"]: x["number"] for x in live}
    print("== %d issues already on %s ==\n" % (len(by_title), REPO))

    todo = backlog[: args.limit] if args.limit else backlog
    created = skipped = 0
    print("== create %d issues ==" % len(todo))
    for issue in todo:
        existing = by_title.get(issue["title"])
        if existing and not args.allow_duplicate_titles:
            print("  SKIP (already #%d): %s" % (existing, issue["title"]))
            skipped += 1
            continue

        labels = ["complexity:" + issue["complexity"], issue["area"]]
        if issue.get("good_first_issue"):
            labels.append("good first issue")
        label_args = []
        for label in labels:
            label_args += ["--label", label]

        if args.apply:
            url = gh("issue", "create", "--repo", REPO, "--title", issue["title"],
                     "--body", render(issue), *label_args).strip()
            print("  %s  %s" % (url, issue["title"]))
            created += 1
        else:
            print("  would create [%-7s %-18s] %s"
                  % (issue["complexity"], issue["area"], issue["title"]))
            if args.bodies:
                print("-" * 70)
                print(render(issue))
                print("-" * 70)
    print()

    # ---- totals ----
    by_complexity = collections.Counter(i["complexity"] for i in backlog)
    by_area = collections.Counter(i["area"] for i in backlog)
    print("=" * 70)
    for level in ("high", "medium", "trivial"):
        n = by_complexity[level]
        print("  %-8s %3d x %3d = %6d points" % (level, n, POINTS[level], n * POINTS[level]))
    total = sum(POINTS[i["complexity"]] for i in backlog)
    print("  %-8s %3d           %6d points" % ("TOTAL", len(backlog), total))
    print()
    for area, n in sorted(by_area.items()):
        print("  %-20s %3d" % (area, n))
    gfi = sum(1 for i in backlog if i.get("good_first_issue"))
    print("\n  good first issues:   %3d" % gfi)

    if args.apply:
        print("\ncreated %d, skipped %d as already present." % (created, skipped))
    else:
        print("\nDRY RUN — nothing was changed. Re-run with --apply.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
