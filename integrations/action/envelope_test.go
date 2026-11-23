package action_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// signedVector reads one committed golden vector and returns the entry the
// reference SDK signed. Using the vectors rather than hand-built entries keeps
// this test honest about the bytes the CLI will actually see.
func signedVector(t *testing.T, name string) (xdr.SorobanAuthorizationEntry, string) {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "vectors", name+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var vector struct {
		SignedEntryXDR string `json:"signed_entry_xdr"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatalf("decoding %s: %v", path, err)
	}
	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(vector.SignedEntryXDR, &entry); err != nil {
		t.Fatalf("decoding the signed entry from %s: %v", path, err)
	}
	return entry, vector.SignedEntryXDR
}

// mixedEnvelope builds one invokeHostFunction operation carrying all four
// credential arms: a source-account entry, a legacy address entry, a V2 entry
// and a delegates entry. That is the shape the issue asks the action to
// summarise, and the shape the host checks in one transaction.
func mixedEnvelope(t *testing.T) string {
	t.Helper()

	legacy, _ := signedVector(t, "legacy_single_testnet")
	v2, _ := signedVector(t, "v2_single_testnet")
	delegates, _ := signedVector(t, "delegates_single_node")

	source := legacy
	source.Credentials = xdr.SorobanCredentials{
		Type: xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount,
	}

	contractAddress, err := xdr.NewScAddress(xdr.ScAddressTypeScAddressTypeContract, xdr.ContractId{7})
	if err != nil {
		t.Fatalf("building the contract address: %v", err)
	}

	op := txnbuild.InvokeHostFunction{
		HostFunction: xdr.HostFunction{
			Type: xdr.HostFunctionTypeHostFunctionTypeInvokeContract,
			InvokeContract: &xdr.InvokeContractArgs{
				ContractAddress: contractAddress,
				FunctionName:    "mixed",
				Args:            []xdr.ScVal{},
			},
		},
		Auth: []xdr.SorobanAuthorizationEntry{source, legacy, v2, delegates},
	}

	kp, err := keypair.Random()
	if err != nil {
		t.Fatalf("generating a source account: %v", err)
	}
	tx, err := txnbuild.NewTransaction(txnbuild.TransactionParams{
		SourceAccount:        &txnbuild.SimpleAccount{AccountID: kp.Address(), Sequence: 0},
		IncrementSequenceNum: true,
		Operations:           []txnbuild.Operation{&op},
		BaseFee:              txnbuild.MinBaseFee,
		Preconditions:        txnbuild.Preconditions{TimeBounds: txnbuild.NewInfiniteTimeout()},
	})
	if err != nil {
		t.Fatalf("building the mixed envelope: %v", err)
	}
	encoded, err := tx.Base64()
	if err != nil {
		t.Fatalf("encoding the mixed envelope: %v", err)
	}
	return encoded
}

// buildCLI builds the real CLI so the action is exercised end to end rather
// than against a mock: the thing that parses the envelope and produces the
// summary is the command the action ships.
func buildCLI(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "soroauth")
	cmd := exec.Command("go", "build", "-o", path, "./cmd/soroauth")
	cmd.Dir = filepath.Join("..", "..")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the CLI: %v\n%s", err, output)
	}
	return path
}

type actionRun struct {
	exit        int
	output      string
	summary     string
	version     string
	annotations []string
}

// runAction runs verify.sh with the given environment overrides and captures
// its output, annotations and job summary.
func runAction(t *testing.T, cli string, env map[string]string) actionRun {
	t.Helper()
	bash, err := findBash()
	if err != nil {
		t.Skipf("bash is required for this test: %v", err)
	}

	tmp := t.TempDir()
	summaryPath := filepath.Join(tmp, "summary.md")
	outputPath := filepath.Join(tmp, "output.txt")

	cmd := exec.Command(bash, "verify.sh")
	cmd.Dir = "."
	cmd.Env = append(os.Environ(),
		"SOROAUTH_INPUT_IMAGE=unused",
		"SOROAUTH_CLI_OVERRIDE="+cli,
		"GITHUB_STEP_SUMMARY="+summaryPath,
		"GITHUB_OUTPUT="+outputPath,
	)
	for key, value := range env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	combined, _ := cmd.CombinedOutput()

	// The exit status is what the action gates on; keep it even when the
	// process wrote output before failing.
	exit := 0
	if cmd.ProcessState != nil {
		exit = cmd.ProcessState.ExitCode()
	}

	summary, _ := os.ReadFile(summaryPath)
	version, _ := os.ReadFile(outputPath)

	var annotations []string
	for _, line := range strings.Split(string(combined), "\n") {
		if strings.HasPrefix(line, "::error") {
			annotations = append(annotations, line)
		}
	}

	return actionRun{
		exit:        exit,
		output:      string(combined),
		summary:     string(summary),
		version:     string(version),
		annotations: annotations,
	}
}

func TestActionVerifiesMixedEnvelopeAndNamesEveryEntry(t *testing.T) {
	cli := buildCLI(t)
	envelope := mixedEnvelope(t)

	run := runAction(t, cli, map[string]string{
		"SOROAUTH_INPUT_ENVELOPE":       envelope,
		"SOROAUTH_INPUT_NETWORK":        "testnet",
		"SOROAUTH_INPUT_ALLOW_UNSIGNED": "true",
	})

	if run.exit != 0 {
		t.Fatalf("action exited %d for a fully signed mixed envelope:\n%s", run.exit, run.output)
	}
	if !strings.Contains(run.output, "4 entries") {
		t.Errorf("output does not report all four entries:\n%s", run.output)
	}

	// Every entry is named by index, and every address-bearing entry carries
	// its address. The source-account arm has no address by definition.
	for _, want := range []string{
		"| 1 | 1 | source_account |",
		"| 1 | 2 | address |",
		"| 1 | 3 | address_v2 |",
		"| 1 | 4 | address_with_delegates |",
	} {
		if !strings.Contains(run.summary, want) {
			t.Errorf("summary does not name entry %q:\n%s", want, run.summary)
		}
	}
	if !strings.Contains(run.summary, "| Operation | Entry | Arm | Address | Verdicts |") {
		t.Errorf("summary has no per-entry table:\n%s", run.summary)
	}
	if !strings.Contains(run.version, "version=") {
		t.Errorf("action did not report the CLI version:\n%s", run.version)
	}
}

func TestActionEnvelopeFailOnUnsigned(t *testing.T) {
	cli := buildCLI(t)

	// Replace the V2 entry with an unsigned one: the source-account entry is
	// still legitimately unsigned, and must not be the reason this fails.
	unsigned, _ := signedVector(t, "v2_single_testnet")
	emptyVec := xdr.ScVec{}
	emptyVecPtr := &emptyVec
	unsigned.Credentials.AddressV2.Signature = xdr.ScVal{
		Type: xdr.ScValTypeScvVec,
		Vec:  &emptyVecPtr,
	}
	envelope := mixedEnvelope(t)

	// Rebuild the envelope with the unsigned V2 entry by decoding the mixed one
	// and replacing entry index 3 (the V2 entry).
	var decoded xdr.TransactionEnvelope
	if err := xdr.SafeUnmarshalBase64(envelope, &decoded); err != nil {
		t.Fatalf("decoding the mixed envelope: %v", err)
	}
	auth := decoded.V1.Tx.Operations[0].Body.InvokeHostFunctionOp.Auth
	auth[2] = unsigned
	decoded.V1.Tx.Operations[0].Body.InvokeHostFunctionOp.Auth = auth
	raw, err := decoded.MarshalBinary()
	if err != nil {
		t.Fatalf("encoding the unsigned envelope: %v", err)
	}
	envelope = base64.StdEncoding.EncodeToString(raw)

	run := runAction(t, cli, map[string]string{
		"SOROAUTH_INPUT_ENVELOPE":       envelope,
		"SOROAUTH_INPUT_NETWORK":        "testnet",
		"SOROAUTH_INPUT_FAIL_ON":        "unsigned",
		"SOROAUTH_INPUT_ALLOW_UNSIGNED": "false",
	})
	if run.exit == 0 {
		t.Fatalf("action passed an envelope with an unsigned address entry:\n%s", run.output)
	}
	if len(run.annotations) == 0 {
		t.Fatalf("action reported no annotation for the unsigned entry:\n%s", run.output)
	}
	joined := strings.Join(run.annotations, "\n")
	if !strings.Contains(joined, "operation 1 entry 3") || !strings.Contains(joined, "unsigned") {
		t.Errorf("annotations do not name the unsigned entry:\n%s", joined)
	}
	// The source-account entry is not a finding.
	if strings.Contains(joined, "source_account") {
		t.Errorf("the source-account entry was reported as the finding:\n%s", joined)
	}
}

func TestActionEnvelopeExpectedArmMismatchFails(t *testing.T) {
	cli := buildCLI(t)

	run := runAction(t, cli, map[string]string{
		"SOROAUTH_INPUT_ENVELOPE":       mixedEnvelope(t),
		"SOROAUTH_INPUT_NETWORK":        "testnet",
		"SOROAUTH_INPUT_EXPECTED_ARM":   "address_v2",
		"SOROAUTH_INPUT_ALLOW_UNSIGNED": "true",
	})
	if run.exit == 0 {
		t.Fatalf("action passed a mixed envelope against one expected arm:\n%s", run.output)
	}
	if !strings.Contains(strings.Join(run.annotations, "\n"), "expected address_v2") {
		t.Errorf("no annotation named the arm mismatch:\n%s", run.output)
	}
}
