package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/soroauth/soroauth-go"
)

const diffUsage = `soroauth diff — compare two authorization entries and report what changed.

usage:
  soroauth diff --before <base64>|[-] --after <base64>|[-] [--json]

Reports the difference between two entries, and — the reason this exists —
separates the changes that invalidate signatures from the ones that do not.

Under CAP-71-01 every credential node of an entry commits to the same payload,
and that payload includes the expiration ledger, the nonce, the invocation tree,
the credential arm, and (for the address-bound arms) the address. A change to
any of those invalidates every signature made against the old entry, even
signatures whose own bytes were never touched. Those are listed as stale: the
entry reads as signed and is rejected by the host rather than locally.

The delegate tree is not part of the payload, so adding or removing a delegate
does not invalidate anyone's signature.

Each change is marked with "!" when it is inside the signed payload.

Without --json the report is written for reading, verdict first. With --json it
is a single object carrying the same verdict in its "summary" field. On error,
--json prints a JSON object with an "error" field to stdout and exits non-zero.

This compares the entries only. The network passphrase is the one part of the
signing payload an entry does not carry, so two entries that differ in nothing
here still have different payloads on different networks; the report says so.

Nothing is signed and no key is involved.

exit codes:
  0  the entries were compared and no signature went stale
  1  general error
  2  usage error (missing --before or --after, or malformed input)
  4  the payload changed and at least one signature was carried over unchanged
`

func runDiff(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("diff", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprint(stderr, diffUsage)
		fmt.Fprintln(stderr, "\nflags:")
		flags.PrintDefaults()
	}

	beforeFlag := flags.String("before", "", "the first authorization entry, as base64 XDR")
	afterFlag := flags.String("after", "", "the second authorization entry, as base64 XDR")
	jsonFlag := flags.Bool("json", false, "print the report as a single JSON object")

	if err := flags.Parse(args); err != nil {
		return newErrorf(ExitUsageError, "%w", err)
	}

	// Only one side can come from stdin, since there is one stream. Saying so
	// is better than reading the same blob twice and reporting two identical
	// entries, which would look like a successful comparison.
	if *beforeFlag == "-" && *afterFlag == "-" {
		return writeJSONError(stdout, *jsonFlag, newErrorf(ExitUsageError,
			"only one of --before and --after can be read from stdin"))
	}

	before, err := decodeEntryNamed("--before", *beforeFlag)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, err)
	}
	after, err := decodeEntryNamed("--after", *afterFlag)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, err)
	}

	report, err := soroauth.DiffEntries(before, after)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, newErrorf(ExitGeneralError, "%w", err))
	}

	if *jsonFlag {
		encoded, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return writeJSONError(stdout, true, newErrorf(ExitGeneralError, "encoding the report: %w", err))
		}
		fmt.Fprintln(stdout, string(encoded))
	} else {
		fmt.Fprint(stdout, report.String())
	}

	// A stale signature is a finding, not a tool failure, so the report is
	// printed in full first and the exit code carries the verdict — the same
	// contract `verify` uses, so one script can treat both the same way.
	if len(report.StaleSignatures) > 0 {
		return newErrorf(ExitVerificationFailed,
			"%d signature(s) carried over unchanged across a payload change", len(report.StaleSignatures))
	}
	return nil
}
