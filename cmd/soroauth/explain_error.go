package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"

	soroauth "github.com/soroauth/soroauth-go"
)

const explainErrorUsage = `soroauth explain-error — explain what a host/RPC error means for an authorization entry.

usage:
  soroauth explain-error --entry <base64> [--network <passphrase>] [--json]

Takes a base64-encoded Soroban authorization entry and reports, for each
credential arm that the host may reject, what the error means in terms of
signature expiration, nonce consumption, or resource budget. The output is
plain text by default, or JSON when --json is given.

exit codes:
  0  success
  1  general error (the entry decoded but could not be inspected)
  2  usage error (invalid flags, missing required flags, malformed input)
`

type explainErrorResult struct {
	Entry     string `json:"entry,omitempty"`
	Network   string `json:"network,omitempty"`
	PlainText string `json:"plain_text"`
	JSON      string `json:"json,omitempty"`
	Error     string `json:"error,omitempty"`
	ErrorExit int    `json:"-"`
}

type explainErrorMapping struct {
	Err          error
	Category     string
	Description  string
	CAP          string // CAP number or "host-source"
	SuggestedFix string
}

var explainErrorMappings = []explainErrorMapping{
	{
		Err:          soroauth.ErrSourceAccountCredentials,
		Category:     "source-account",
		Description:  "the transaction source account itself is being authorized; no signature is needed",
		CAP:          "CAP-46-11 §3",
		SuggestedFix: "ensure the source account is authorized via the transaction envelope, not a credential node",
	},
	{
		Err:          soroauth.ErrInvalidExpiration,
		Category:     "expiration",
		Description:  "signatureExpirationLedger is in the past (current_ledger > signatureExpirationLedger)",
		CAP:          "CAP-71-01 §5.1",
		SuggestedFix: "increase signatureExpirationLedger to a future ledger or use ExpirationAfter to compute it",
	},
	{
		Err:          soroauth.ErrMissingSigner,
		Category:     "missing-signer",
		Description:  "no signer was found whose Address() matches the entry's top-level credentials",
		CAP:          "CAP-71-01 §5.2",
		SuggestedFix: "provide a signer whose address matches the credential's address, or use --for to specify the target",
	},
	{
		Err:          soroauth.ErrNoMatchingCredentialNode,
		Category:     "no-matching-node",
		Description:  "the entry has no credential node whose address equals the target; or the delegates arm has no nodes matching the signer's address",
		CAP:          "CAP-71-01 §5.3",
		SuggestedFix: "ensure the signer's address appears in the delegates arm, or the entry has a top-level address matching the signer",
	},
	{
		Err:          soroauth.ErrAlreadySigned,
		Category:     "already-signed",
		Description:  "a node already has a non-Void, non-empty signature; re-signing would invalidate other nodes",
		CAP:          "CAP-71-01 §5.4",
		SuggestedFix: "use --allow-resign if you intentionally want to overwrite, or check the expiration mismatch first",
	},
	{
		Err:          soroauth.ErrUnsupportedCredentials,
		Category:     "unsupported",
		Description:  "the credential arm is not (yet) supported by this library version",
		CAP:          "CAP-71-02 §2",
		SuggestedFix: "upgrade the entry to a supported arm or check the library version",
	},
	{
		Err:          fmt.Errorf("signature verification failed: signature mismatch"),
		Category:     "signature-mismatch",
		Description:  "the signature on a credential node does not match the preimage payload",
		CAP:          "CAP-71-01 §5.5",
		SuggestedFix: "re-sign the entry with the correct key; verify the signer's key matches the credential's address",
	},
	{
		Err:          fmt.Errorf("too many signatures"),
		Category:     "too-many-signatures",
		Description:  "more than the allowed number of signatures on a single credential node",
		CAP:          "CAP-71-01 §5.6",
		SuggestedFix: "reduce the number of signatures; account multisigs are capped at 20 signers",
	},
	{
		Err:          fmt.Errorf("nonce already consumed"),
		Category:     "nonce-consumed",
		Description:  "the nonce has already been consumed in a previous authorization check; the host will reject the transaction",
		CAP:          "CAP-71-01 §5.1",
		SuggestedFix: "use a fresh nonce; do not reuse the same nonce across multiple authorizations",
	},
	{
		Err:          fmt.Errorf("resource budget exceeded"),
		Category:     "resource-budget",
		Description:  "the transaction exceeded the host's resource budget (e.g., too many instructions, too deep a call tree)",
		CAP:          "CAP-46-11 §4",
		SuggestedFix: "reduce the call tree depth or sub-invocations; the contract may have hit an instruction limit",
	},
	{
		Err:          fmt.Errorf("unknown delegate"),
		Category:     "unknown-delegate",
		Description:  "a delegate in the delegates arm is not registered in the modular account's stored signers",
		CAP:          "CAP-71-01 §5.7",
		SuggestedFix: "register the delegate in the account's stored signers, or ensure the delegate is authorized via a different path",
	},
	{
		Err:          fmt.Errorf("contract error: unknown delegate"),
		Category:     "contract-unknown-delegate",
		Description:  "the Soroban host returned an UnknownDelegate error when checking delegated authorization",
		CAP:          "CAP-71-01 §5.7 / host source",
		SuggestedFix: "register the delegate in the account's stored signers before submitting; use the modular account's grant_delegate flow",
	},
	{
		Err:          fmt.Errorf("contract error: no delegates"),
		Category:     "contract-no-delegates",
		Description:  "the Soroban host returned a NoDelegates error when checking delegated authorization because the account has zero stored signers",
		CAP:          "CAP-71-01 §5.7 / host source",
		SuggestedFix: "ensure the account has at least one signer registered before authorizing via delegates",
	},
}

func init() {
	if err := registerExplainError(); err != nil {
		panic(fmt.Sprintf("failed to register explain-error: %v", err))
	}
}

func registerExplainError() error {
	// Validation at registration time: ensure all Err values are non-nil
	for i, m := range explainErrorMappings {
		if m.Err == nil {
			return fmt.Errorf("explain-error mapping %d has nil Err", i)
		}
		if m.Category == "" {
			return fmt.Errorf("explain-error mapping %d has empty Category", i)
		}
		if m.Description == "" {
			return fmt.Errorf("explain-error mapping %d has empty Description", i)
		}
		if m.CAP == "" {
			return fmt.Errorf("explain-error mapping %d has empty CAP", i)
		}
		if m.SuggestedFix == "" {
			return fmt.Errorf("explain-error mapping %d has empty SuggestedFix", i)
		}
	}
	return nil
}

func runExplainError(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("explain-error", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, explainErrorUsage)
		fmt.Fprint(stderr, "\nFlags:\n")
		fs.PrintDefaults()
	}

	var entryB64 string
	var network string
	var jsonOutput bool

	fs.StringVar(&entryB64, "entry", "", "base64-encoded Soroban authorization entry (required)")
	fs.StringVar(&network, "network", "", "network passphrase: testnet, futurenet, public, rpc, or literal (optional)")
	fs.BoolVar(&jsonOutput, "json", false, "output the result as JSON")
	registerVerbosityFlags(fs)

	if err := fs.Parse(args); err != nil {
		return writeJSONError(stdout, jsonOutput, newErrorf(ExitUsageError, "%w", err))
	}

	if entryB64 == "" {
		return writeJSONError(stdout, jsonOutput, withField("--entry", newErrorf(ExitUsageError, "--entry is required")))
	}

	// Decode the entry
	entry, err := decodeEntry(entryB64)
	if err != nil {
		return writeJSONError(stdout, jsonOutput, withField("--entry", newErrorf(ExitUsageError, "decoding --entry: %w", err)))
	}

	// Inspect the entry to get credential type
	entryInfo, inspectErr := soroauth.Inspect(entry)
	if inspectErr != nil {
		// An entry that cannot be inspected cannot be explained, so this is a
		// failure in both modes. Text mode used to print the error and exit 0,
		// which a script would read as success.
		return writeJSONError(stdout, jsonOutput, withField("--entry", newErrorf(ExitGeneralError, "inspecting --entry: %w", inspectErr)))
	}

	// Generate explanations based on the entry info
	var explanations []string

	switch entryInfo.CredentialType {
	case "source_account":
		explanations = append(explanations, fmt.Sprintf("Credential type: source_account (SOROBAN_CREDENTIALS_SOURCE_ACCOUNT)"))
		explanations = append(explanations, fmt.Sprintf("This arm authorizes the transaction source account directly via the envelope."))
		explanations = append(explanations, fmt.Sprintf("CAP reference: %s", explainErrorMappings[0].CAP))
		explanations = append(explanations, fmt.Sprintf("Suggested fix: %s", explainErrorMappings[0].SuggestedFix))

	case "address":
		explanations = append(explanations, fmt.Sprintf("Credential type: address (SOROBAN_CREDENTIALS_ADDRESS, legacy V1)"))
		explanations = append(explanations, fmt.Sprintf("Address: %s", entryInfo.Address))
		explanations = append(explanations, fmt.Sprintf("Nonce: %d", entryInfo.Nonce))
		explanations = append(explanations, fmt.Sprintf("ValidUntilLedger: %d", entryInfo.ValidUntilLedger))
		explanations = append(explanations, fmt.Sprintf("TopLevelSigned: %v", entryInfo.TopLevelSigned))

		// Check expiration
		if entryInfo.ValidUntilLedger > 0 {
			explanations = append(explanations, fmt.Sprintf("Expiration check: signatureExpirationLedger=%d; if current_ledger > this, the host will reject", entryInfo.ValidUntilLedger))
		}

		// Check nonce
		if entryInfo.Nonce != 0 {
			explanations = append(explanations, fmt.Sprintf("Nonce: %d; ensure it has not been consumed in a prior authorization check", entryInfo.Nonce))
		}

		explanations = append(explanations, fmt.Sprintf("CAP reference: %s", explainErrorMappings[1].CAP))
		explanations = append(explanations, fmt.Sprintf("Suggested fix: %s", explainErrorMappings[1].SuggestedFix))

	case "address_v2":
		explanations = append(explanations, fmt.Sprintf("Credential type: address_v2 (SOROBAN_CREDENTIALS_ADDRESS_V2)"))
		explanations = append(explanations, fmt.Sprintf("Address: %s", entryInfo.Address))
		explanations = append(explanations, fmt.Sprintf("Nonce: %d", entryInfo.Nonce))
		explanations = append(explanations, fmt.Sprintf("ValidUntilLedger: %d", entryInfo.ValidUntilLedger))

		if entryInfo.ValidUntilLedger > 0 {
			explanations = append(explanations, fmt.Sprintf("Expiration check: signatureExpirationLedger=%d; if current_ledger > this, the host will reject", entryInfo.ValidUntilLedger))
		}

		if entryInfo.Nonce != 0 {
			explanations = append(explanations, fmt.Sprintf("Nonce: %d; ensure it has not been consumed", entryInfo.Nonce))
		}

		explanations = append(explanations, fmt.Sprintf("CAP reference: %s", explainErrorMappings[2].CAP))
		explanations = append(explanations, fmt.Sprintf("Suggested fix: %s", explainErrorMappings[2].SuggestedFix))

	case "address_with_delegates":
		explanations = append(explanations, fmt.Sprintf("Credential type: address_with_delegates (SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES)"))
		explanations = append(explanations, fmt.Sprintf("Address: %s", entryInfo.Address))
		explanations = append(explanations, fmt.Sprintf("Nonce: %d", entryInfo.Nonce))
		explanations = append(explanations, fmt.Sprintf("ValidUntilLedger: %d", entryInfo.ValidUntilLedger))
		explanations = append(explanations, fmt.Sprintf("TopLevelSigned: %v", entryInfo.TopLevelSigned))
		explanations = append(explanations, fmt.Sprintf("Delegates: %d delegate(s)", len(entryInfo.Delegates)))

		if entryInfo.ValidUntilLedger > 0 {
			explanations = append(explanations, fmt.Sprintf("Expiration check: signatureExpirationLedger=%d; if current_ledger > this, the host will reject", entryInfo.ValidUntilLedger))
		}

		if entryInfo.Nonce != 0 {
			explanations = append(explanations, fmt.Sprintf("Nonce: %d; ensure it has not been consumed", entryInfo.Nonce))
		}

		explanations = append(explanations, fmt.Sprintf("CAP reference: %s", explainErrorMappings[3].CAP))
		explanations = append(explanations, fmt.Sprintf("Suggested fix: %s", explainErrorMappings[3].SuggestedFix))

	default:
		explanations = append(explanations, fmt.Sprintf("Unknown credential type: %s", entryInfo.CredentialType))
		explanations = append(explanations, fmt.Sprintf("This may be an unsupported arm; see ErrUnsupportedCredentials"))
	}

	result := explainErrorResult{
		Entry:     entryB64,
		PlainText: strings.Join(explanations, "\n"),
	}

	if jsonOutput {
		b, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return writeJSONError(stdout, true, newErrorf(ExitGeneralError, "encoding result as JSON: %w", err))
		}
		fmt.Fprintln(stdout, string(b))
	} else {
		fmt.Fprintln(stdout, result.PlainText)
	}

	return nil
}
