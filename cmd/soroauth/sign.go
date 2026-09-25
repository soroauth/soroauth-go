package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

const signUsage = `soroauth sign — sign an authorization entry.

usage:
  soroauth sign --entry <base64> --valid-until <ledger> --network <name|passphrase> \
                --secret-env <VAR> [--for <address>] [--json]

--entry accepts either an authorization entry or a whole transaction envelope,
and the tool works out which it was given. Given an envelope it signs every
authorization entry the envelope carries and prints the envelope back; a
fee-bump envelope is read through to its inner transaction, which is where the
entries live.

A wallet that has just signed entries must run a second simulation in enforce
mode before submitting: signing changes what the transaction costs to run, and
a transaction assembled from the record-mode simulation will be rejected on
resource fees. This command signs entries only — it does not simulate, and it
does not sign the envelope itself, which is the source account's (or the
fee-bump fee source's) signature, not an authorization entry.

The signing seed is read from the environment variable named by --secret-env.
There is deliberately no flag that takes a seed as a value: a flag value ends up
in shell history, in the process table, and in any transcript of the session.

The signature is written only onto credential nodes whose address matches the
signer's own address, or the address given by --for. If no node matches, the
command fails rather than signing something else. --for applies to a single
entry and is refused for an envelope, where it would have to mean something
different per entry.

Prints the signed entry as base64, or the signed envelope as base64 when given
an envelope. With --json, prints a JSON object with field "signed_entry", or
"signed_envelope". On error, prints a JSON object with field "error" to stdout
and exits non-zero.
`

type signOutput struct {
	SignedEntry    string `json:"signed_entry,omitempty"`
	SignedEnvelope string `json:"signed_envelope,omitempty"`
	Error          string `json:"error,omitempty"`
}

func runSign(args []string, stdout, stderr io.Writer, getenv func(string) string) error {
	flags := flag.NewFlagSet("sign", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprint(stderr, signUsage)
		fmt.Fprintln(stderr, "\nflags:")
		flags.PrintDefaults()
	}

	entryFlag := flags.String("entry", "", "the authorization entry or transaction envelope, as base64 XDR")
	validUntil := flags.Uint("valid-until", 0, "the last ledger at which the signature is valid")
	networkFlag := flags.String("network", "", "testnet, public, or a literal network passphrase")
	secretEnv := flags.String("secret-env", "", "name of the environment variable holding the S… seed")
	forAddress := flags.String("for", "", "credential node to sign, when it is not the signer's own address")
	jsonFlag := flags.Bool("json", false, "output as JSON")

	if err := flags.Parse(args); err != nil {
		return newErrorf(ExitUsageError, "%w", err)
	}

	input, err := decodeEntryOrEnvelope(*entryFlag)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, err)
	}
	passphrase, err := resolveNetwork(*networkFlag)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, err)
	}
	if *validUntil == 0 {
		return writeJSONError(stdout, *jsonFlag, newErrorf(ExitUsageError, "--valid-until is required and must be greater than zero"))
	}
	if *secretEnv == "" {
		return writeJSONError(stdout, *jsonFlag, newErrorf(ExitUsageError, "--secret-env is required: name the environment variable holding the seed"))
	}

	seed := getenv(*secretEnv)
	if seed == "" {
		return writeJSONError(stdout, *jsonFlag, newErrorf(ExitUsageError, "environment variable %s is empty or unset", *secretEnv))
	}

	// keypair.Parse's error can quote what it was given, so it is deliberately
	// not wrapped: the message names the variable, never its contents.
	parsed, err := keypair.Parse(seed)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, newErrorf(ExitUsageError, "the value of %s is not a valid Stellar key", *secretEnv))
	}
	full, ok := parsed.(*keypair.Full)
	if !ok {
		return writeJSONError(stdout, *jsonFlag, newErrorf(ExitUsageError, "the value of %s is a public key; a secret seed (S…) is required", *secretEnv))
	}
	signer := soroauth.NewEd25519Signer(full)

	// An envelope carries entries for whatever addresses simulation recorded,
	// so a single target address would be ambiguous: it would have to apply to
	// one of them and not the others. Refusing is the fail-closed reading.
	if input.IsEnvelope && *forAddress != "" {
		return writeJSONError(stdout, *jsonFlag, newErrorf(ExitUsageError,
			"--for applies to a single entry; given an envelope, sign the entries one at a time or drop --for"))
	}

	if input.IsEnvelope {
		signed, err := soroauth.AuthorizeEnvelope(context.Background(), input.Envelope,
			[]soroauth.Signer{signer}, uint32(*validUntil), passphrase)
		if err != nil {
			return writeJSONError(stdout, *jsonFlag, newErrorf(exitCodeForSigningError(err), "%w", err))
		}

		encoded, err := xdr.MarshalBase64(signed)
		if err != nil {
			return writeJSONError(stdout, *jsonFlag, newErrorf(ExitGeneralError, "encoding the signed envelope: %w", err))
		}
		if *jsonFlag {
			enc := json.NewEncoder(stdout)
			enc.SetEscapeHTML(false)
			return enc.Encode(signOutput{SignedEnvelope: encoded})
		}
		fmt.Fprintln(stdout, encoded)
		return nil
	}

	var opts []soroauth.AuthorizeOption
	if *forAddress != "" {
		opts = append(opts, soroauth.ForAddress(*forAddress))
	}

	signed, err := soroauth.AuthorizeEntry(context.Background(), input.Entry,
		signer, uint32(*validUntil), passphrase, opts...)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, newErrorf(exitCodeForSigningError(err), "%w", err))
	}

	encoded, err := encodeEntry(signed)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, newErrorf(ExitGeneralError, "%w", err))
	}

	if *jsonFlag {
		out := signOutput{SignedEntry: encoded}
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		return enc.Encode(out)
	}

	fmt.Fprintln(stdout, encoded)
	return nil
}

// exitCodeForSigningError maps a refusal or a verification failure onto the
// exit code that classifies it, so both the entry and the envelope paths report
// the same way.
func exitCodeForSigningError(err error) int {
	switch {
	case errors.Is(err, soroauth.ErrNoMatchingCredentialNode),
		errors.Is(err, soroauth.ErrAlreadySigned),
		errors.Is(err, soroauth.ErrSourceAccountCredentials),
		errors.Is(err, soroauth.ErrUnsupportedCredentials),
		errors.Is(err, soroauth.ErrDuplicateDelegate),
		errors.Is(err, soroauth.ErrMissingSigner),
		errors.Is(err, soroauth.ErrNoInvokeOperation),
		errors.Is(err, soroauth.ErrUnsupportedEnvelope):
		return ExitSigningRefusal
	case errors.Is(err, soroauth.ErrSignatureMismatch),
		errors.Is(err, soroauth.ErrInvalidExpiration),
		errors.Is(err, soroauth.ErrTooManySignatures):
		return ExitVerificationFailed
	default:
		return ExitGeneralError
	}
}
