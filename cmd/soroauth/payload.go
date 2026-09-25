package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

const payloadUsage = `soroauth payload — print what a signer would have to sign.

usage:
  soroauth payload --entry <base64> --valid-until <ledger> --network <name|passphrase> [--json]

--entry accepts either an authorization entry or a whole transaction envelope,
and the tool works out which it was given. An envelope produces one report per
authorization entry, in operation order, each carrying the operation_index and
entry_index it came from; a fee-bump envelope is read through to the inner
transaction. Entries on the source-account arm are reported with
source_account true and no preimage or payload, because they have none of their
own — the envelope's signature covers them.

Prints the HashIdPreimage as base64 and its SHA-256 payload as hex. Nothing is
signed and no key is involved, so this is the subcommand to use when checking
what an offline or hardware signer is being asked to approve.

With --json, prints a single JSON object with fields "preimage" and "payload"
for a single entry, or an array of objects with those fields plus
"operation_index", "entry_index" and "source_account" for an envelope. On
error, prints a JSON object with field "error" to stdout and exits non-zero.
`

type payloadOutput struct {
	Preimage string `json:"preimage,omitempty"`
	Payload  string `json:"payload,omitempty"`
	Error    string `json:"error,omitempty"`
}

// envelopePayloadOutput is one entry's payload report, with the position it
// came from.
type envelopePayloadOutput struct {
	OperationIndex int    `json:"operation_index"`
	EntryIndex     int    `json:"entry_index"`
	SourceAccount  bool   `json:"source_account,omitempty"`
	Preimage       string `json:"preimage,omitempty"`
	Payload        string `json:"payload,omitempty"`
}

func runPayload(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("payload", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprint(stderr, payloadUsage)
		fmt.Fprintln(stderr, "\nflags:")
		flags.PrintDefaults()
	}

	entryFlag := flags.String("entry", "", "the authorization entry or transaction envelope, as base64 XDR")
	validUntil := flags.Uint("valid-until", 0, "the last ledger at which the signature is valid")
	networkFlag := flags.String("network", "", "testnet, public, or a literal network passphrase")
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

	if input.IsEnvelope {
		return runPayloadEnvelope(stdout, input.Envelope, uint32(*validUntil), passphrase, *jsonFlag)
	}

	preimage, err := soroauth.Preimage(input.Entry, uint32(*validUntil), passphrase)
	if err != nil {
		// Classify the error for exit code
		var exitCode int
		if errors.Is(err, soroauth.ErrSourceAccountCredentials) || errors.Is(err, soroauth.ErrUnsupportedCredentials) {
			exitCode = ExitSigningRefusal
		} else {
			exitCode = ExitVerificationFailed
		}
		return writeJSONError(stdout, *jsonFlag, newErrorf(exitCode, "%w", err))
	}
	payload, err := soroauth.Payload(preimage)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, newErrorf(ExitGeneralError, "%w", err))
	}
	encoded, err := xdr.MarshalBase64(preimage)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, newErrorf(ExitGeneralError, "encoding the preimage: %w", err))
	}

	if *jsonFlag {
		out := payloadOutput{Preimage: encoded, Payload: hex.EncodeToString(payload[:])}
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		return enc.Encode(out)
	}

	fmt.Fprintf(stdout, "preimage: %s\n", encoded)
	fmt.Fprintf(stdout, "payload:  %s\n", hex.EncodeToString(payload[:]))
	return nil
}

// runPayloadEnvelope reports the payload of every authorization entry in an
// envelope, in operation order.
//
// It computes each payload from the entry as it is stored, so what it prints
// is what a signature over that entry has to cover. A source-account entry is
// reported rather than skipped, with no payload, because the absence is the
// thing a caller needs to know: there is nothing for a key to sign there.
func runPayloadEnvelope(
	stdout io.Writer,
	envelope xdr.TransactionEnvelope,
	validUntil uint32,
	passphrase string,
	jsonFlag bool,
) error {
	payloads, err := soroauth.EnvelopePayloads(envelope, validUntil, passphrase)
	if err != nil {
		var exitCode int
		if errors.Is(err, soroauth.ErrSourceAccountCredentials) || errors.Is(err, soroauth.ErrUnsupportedCredentials) {
			exitCode = ExitSigningRefusal
		} else {
			exitCode = ExitVerificationFailed
		}
		return writeJSONError(stdout, jsonFlag, newErrorf(exitCode, "%w", err))
	}

	out := make([]envelopePayloadOutput, 0, len(payloads))
	for _, payload := range payloads {
		item := envelopePayloadOutput{
			OperationIndex: payload.OperationIndex,
			EntryIndex:     payload.EntryIndex,
			SourceAccount:  payload.SourceAccount,
		}
		if !payload.SourceAccount {
			encoded, err := xdr.MarshalBase64(payload.Preimage)
			if err != nil {
				return writeJSONError(stdout, jsonFlag, newErrorf(ExitGeneralError, "encoding the preimage: %w", err))
			}
			item.Preimage = encoded
			item.Payload = hex.EncodeToString(payload.Payload[:])
		}
		out = append(out, item)
	}

	if jsonFlag {
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		return enc.Encode(out)
	}

	for _, item := range out {
		if item.SourceAccount {
			fmt.Fprintf(stdout, "operation %d entry %d: source-account credentials, which carry no payload\n",
				item.OperationIndex, item.EntryIndex)
			continue
		}
		fmt.Fprintf(stdout, "operation %d entry %d preimage: %s\n", item.OperationIndex, item.EntryIndex, item.Preimage)
		fmt.Fprintf(stdout, "operation %d entry %d payload:  %s\n", item.OperationIndex, item.EntryIndex, item.Payload)
	}
	return nil
}
