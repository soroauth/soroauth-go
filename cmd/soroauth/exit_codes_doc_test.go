package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// exitCodeCLIEnv, when set in a re-executed test binary, makes TestMain run
// the real main() instead of the test suite. That is how the exit-code test
// drives the CLI as a subprocess and observes the process's real exit status,
// without depending on a separately built binary or a Go toolchain at test
// time.
const exitCodeCLIEnv = "SOROAUTH_TEST_RUN_CLI_MAIN"

func TestMain(m *testing.M) {
	if os.Getenv(exitCodeCLIEnv) == "1" {
		main()
		os.Exit(ExitOK)
	}
	os.Exit(m.Run())
}

// globalScope keys the exit codes documented for the whole CLI: the EXIT
// CODES section of docs/soroauth.1 and the top-level --help. A subcommand
// whose own usage text has no "exit codes:" block is held to these.
const globalScope = "(global)"

// parseUsageBlock returns the entries of the indented block that follows the
// line `header` (e.g. "exit codes:") in a usage text, keyed by the block's
// first column. found is false when the text has no such block.
func parseUsageBlock(text, header string) (block map[string]string, found bool) {
	block = map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(text))
	in := false
	for scanner.Scan() {
		line := scanner.Text()
		if !in {
			if strings.TrimSpace(line) == header {
				in, found = true, true
			}
			continue
		}
		if strings.TrimSpace(line) == "" || !strings.HasPrefix(line, " ") {
			break
		}
		fields := strings.Fields(line)
		block[fields[0]] = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), fields[0]))
	}
	return block, found
}

// parseExitCodes parses an "exit codes:" block into code -> description.
func parseExitCodes(t *testing.T, source, text string) (map[int]string, bool) {
	t.Helper()
	raw, found := parseUsageBlock(text, "exit codes:")
	if !found {
		return nil, false
	}
	codes := map[int]string{}
	for k, desc := range raw {
		code, err := strconv.Atoi(k)
		if err != nil {
			t.Fatalf("%s: exit codes block has a non-numeric code %q", source, k)
		}
		codes[code] = desc
	}
	if len(codes) == 0 {
		t.Fatalf("%s: exit codes block is empty", source)
	}
	return codes, true
}

// parseManExitCodes reads the EXIT CODES section of the committed man page:
// a run of `.TP` / `.B <code>` / `<description>` triples up to the next `.SH`.
func parseManExitCodes(t *testing.T, page string) map[int]string {
	t.Helper()
	start := strings.Index(page, ".SH EXIT CODES\n")
	if start < 0 {
		t.Fatal("docs/soroauth.1 has no .SH EXIT CODES section")
	}
	section := page[start+len(".SH EXIT CODES\n"):]
	if end := strings.Index(section, "\n.SH "); end >= 0 {
		section = section[:end]
	}
	lines := strings.Split(section, "\n")
	codes := map[int]string{}
	for i := 0; i+2 < len(lines); i++ {
		if lines[i] != ".TP" || !strings.HasPrefix(lines[i+1], ".B ") {
			continue
		}
		code, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(lines[i+1], ".B ")))
		if err != nil {
			t.Fatalf("docs/soroauth.1 EXIT CODES: %q is not a code", lines[i+1])
		}
		codes[code] = lines[i+2]
	}
	if len(codes) == 0 {
		t.Fatal("docs/soroauth.1 EXIT CODES section documents no code")
	}
	return codes
}

// cliRun is one subprocess invocation and its observed exit status.
type cliRun struct {
	code   int
	output string
}

// runCLIProcess runs the real main() in a child process with args, the given
// extra environment, and stdin, and returns its exit status. The child
// inherits the parent's environment minus every SOROAUTH_* variable, with
// XDG_CONFIG_HOME pointed at an empty directory, so neither a developer's
// shell nor their config file can change which code comes back.
func runCLIProcess(t *testing.T, configHome string, env map[string]string, stdin string, args ...string) cliRun {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("locating the test binary: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, self, args...)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "SOROAUTH_") || strings.HasPrefix(kv, "XDG_CONFIG_HOME=") {
			continue
		}
		cmd.Env = append(cmd.Env, kv)
	}
	cmd.Env = append(cmd.Env, exitCodeCLIEnv+"=1", "XDG_CONFIG_HOME="+configHome)
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Stdin = strings.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err = cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("soroauth %s timed out", strings.Join(args, " "))
	}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return cliRun{code: 0, output: out.String()}
	case errors.As(err, &exitErr):
		return cliRun{code: exitErr.ExitCode(), output: out.String()}
	default:
		t.Fatalf("running soroauth %s: %v", strings.Join(args, " "), err)
		return cliRun{}
	}
}

// encodeTestEntry encodes an entry for a flag value, failing the test on error.
func encodeTestEntry(t *testing.T, entry xdr.SorobanAuthorizationEntry) string {
	t.Helper()
	encoded, err := encodeEntry(entry)
	if err != nil {
		t.Fatalf("encoding an entry: %v", err)
	}
	return encoded
}

// TestDocumentedExitCodesMatchTheCLI ties the documented exit codes to the
// ones the CLI actually returns, in both directions (#669).
//
// The exit codes are an interface people script against, so the
// documentation is the source of truth and is parsed, never restated here:
//
//   - the global codes come from the EXIT CODES section of docs/soroauth.1,
//     and the top-level --help must list the same codes;
//   - a subcommand whose -h output carries its own "exit codes:" block is held
//     to that block (diff's stale-signature code lives there); any other
//     subcommand is held to the global codes.
//
// Every scenario runs the real main() in a subprocess. A code it returns that
// its documentation does not list fails the test, and so does a documented
// code no scenario produces. Each scenario also names a phrase from the
// description its code should carry, so a scenario that starts returning a
// different documented code for the wrong reason is caught too — without the
// test ever spelling a code number.
func TestDocumentedExitCodesMatchTheCLI(t *testing.T) {
	configHome := t.TempDir()

	page, err := os.ReadFile(filepath.Join("..", "..", "docs", "soroauth.1"))
	if err != nil {
		t.Fatalf("reading docs/soroauth.1: %v", err)
	}
	documented := map[string]map[int]string{globalScope: parseManExitCodes(t, string(page))}

	help := runCLIProcess(t, configHome, nil, "", "--help")
	helpCodes, found := parseExitCodes(t, "soroauth --help", help.output)
	if !found {
		t.Fatalf("soroauth --help documents no exit codes:\n%s", help.output)
	}
	if got, want := sortedCodes(helpCodes), sortedCodes(documented[globalScope]); !equalInts(got, want) {
		t.Errorf("soroauth --help documents exit codes %v, docs/soroauth.1 documents %v; the two must agree", got, want)
	}

	// The subcommands come from the top-level help's own command list, so a
	// command added there is held to its documentation without editing this test.
	commandBlock, found := parseUsageBlock(help.output, "commands:")
	if !found || len(commandBlock) == 0 {
		t.Fatalf("soroauth --help lists no commands:\n%s", help.output)
	}
	scopeOf := map[string]string{"": globalScope}
	for command := range commandBlock {
		usage := runCLIProcess(t, configHome, nil, "", command, "-h")
		if codes, own := parseExitCodes(t, "soroauth "+command+" -h", usage.output); own {
			documented[command] = codes
			scopeOf[command] = command
		} else {
			scopeOf[command] = globalScope
		}
		// Asking for help is an invocation like any other: its status must be
		// documented too.
		if _, ok := documented[scopeOf[command]][usage.code]; !ok {
			t.Errorf("soroauth %s -h exits %d, which %s does not document", command, usage.code, scopeName(scopeOf[command]))
		}
	}

	// Fixtures: committed golden vectors and RPC responses, not invented bytes.
	v := loadVector(t, "v2_single_testnet")
	stranger := vectorKeypair(t, "soroauth-vector-delegate-3")

	signed, err := decodeEntry(v.SignedEntryXDR)
	if err != nil {
		t.Fatalf("decoding the vector's signed entry: %v", err)
	}
	// The same signature carried over onto an entry whose nonce, and so whose
	// payload, changed: the stale signature diff exists to report.
	stale, err := decodeEntry(v.SignedEntryXDR)
	if err != nil {
		t.Fatalf("decoding the vector's signed entry: %v", err)
	}
	stale.Credentials.AddressV2.Nonce++
	// A muxed credential address decodes as valid XDR but is refused by
	// Inspect, which is the CLI's general-error path for an entry it cannot
	// report on.
	muxed, err := decodeEntry(v.UnsignedEntryXDR)
	if err != nil {
		t.Fatalf("decoding the vector's unsigned entry: %v", err)
	}
	var key xdr.Uint256
	copy(key[:], stranger.Address()) // any 32 bytes; the key is never used
	muxed.Credentials.AddressV2.Address = xdr.ScAddress{
		Type:         xdr.ScAddressTypeScAddressTypeMuxedAccount,
		MuxedAccount: &xdr.MuxedEd25519Account{Id: 1, Ed25519: key},
	}
	muxedXDR := encodeTestEntry(t, muxed)

	fixtures := loadRPCFixtures(t)
	rpcOK := newFakeRPC(t, fixtures)
	rpcHostError := newFakeRPC(t, fixtures)
	rpcHostError.failSimulate = "HostError: Error(WasmVm, InvalidAction)"
	rpcTxFailed := newFakeRPC(t, fixtures)
	rpcTxFailed.failPoll = true
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(healthy.Close)
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(broken.Close)

	payer := map[string]string{"SEED": testPayer(t).Seed()}
	signedEnvelope := envelopeWithEntries(t, testPayerAddress(t), "1", signedVectorEntries(t)...)
	unsignedEnvelope := envelopeWithEntries(t, testPayerAddress(t), "1")

	writeWasm := func(size int) string {
		path := filepath.Join(t.TempDir(), "artifact.wasm")
		if err := os.WriteFile(path, make([]byte, size), 0o600); err != nil {
			t.Fatalf("writing a wasm artifact: %v", err)
		}
		return path
	}
	smallWasm, largeWasm := writeWasm(1024), writeWasm(4096)

	scenarios := []struct {
		name string
		args []string
		env  map[string]string
		// meaning is a phrase the documented description of the observed
		// code must contain, case-insensitively.
		meaning string
	}{
		// Global codes, on subcommands that document none of their own.
		{"version", []string{"--version"}, nil, "success"},
		{"no command", nil, nil, "usage error"},
		{"unknown command", []string{"no-such-command"}, nil, "usage error"},
		{"payload", []string{"payload", "--entry", v.UnsignedEntryXDR, "--valid-until", "1234567", "--network", "testnet"}, nil, "success"},
		{"payload without --entry", []string{"payload", "--valid-until", "1", "--network", "testnet"}, nil, "usage error"},
		{"payload with an unreachable --network rpc", []string{"payload", "--entry", v.UnsignedEntryXDR, "--valid-until", "1234567", "--network", "rpc", "--rpc-url", broken.URL}, nil, "general error"},
		{"sign with a key that owns no node", []string{"sign", "--entry", v.UnsignedEntryXDR, "--valid-until", "1234567", "--network", "testnet", "--secret-env", "SEED"}, map[string]string{"SEED": stranger.Seed()}, "signing refused"},
		{"verify an unsigned entry", []string{"verify", "--entry", v.UnsignedEntryXDR, "--network", "testnet"}, nil, "verification failed"},
		{"verify a signed entry", []string{"verify", "--entry", v.SignedEntryXDR, "--network", "testnet"}, nil, "success"},

		// diff documents its own codes, including the stale-signature one.
		{"diff identical entries", []string{"diff", "--before", v.SignedEntryXDR, "--after", v.SignedEntryXDR}, nil, "no signature went stale"},
		{"diff a signature carried across a payload change", []string{"diff", "--before", encodeTestEntry(t, signed), "--after", encodeTestEntry(t, stale)}, nil, "carried over unchanged"},
		{"diff without --after", []string{"diff", "--before", v.SignedEntryXDR}, nil, "usage error"},
		{"diff an entry that cannot be inspected", []string{"diff", "--before", muxedXDR, "--after", muxedXDR}, nil, "general error"},

		{"inspect", []string{"inspect", "--entry", v.UnsignedEntryXDR}, nil, "success"},
		{"inspect without --entry", []string{"inspect"}, nil, "usage error"},
		{"inspect an entry that cannot be inspected", []string{"inspect", "--entry", muxedXDR}, nil, "general error"},

		{"tree", []string{"tree", "--entry", v.UnsignedEntryXDR}, nil, "success"},
		{"tree with an unknown --format", []string{"tree", "--entry", v.UnsignedEntryXDR, "--format", "svg"}, nil, "usage error"},
		{"tree of an entry that cannot be inspected", []string{"tree", "--entry", muxedXDR}, nil, "general error"},

		{"explain-error", []string{"explain-error", "--entry", v.UnsignedEntryXDR}, nil, "success"},
		{"explain-error without --entry", []string{"explain-error"}, nil, "usage error"},
		{"explain-error on an entry that cannot be inspected", []string{"explain-error", "--entry", muxedXDR}, nil, "general error"},
		{"explain-error --json on an entry that cannot be inspected", []string{"explain-error", "--entry", muxedXDR, "--json"}, nil, "general error"},

		{"man", []string{"man"}, nil, "success"},
		{"man with --json and --out", []string{"man", "--json", "--out", filepath.Join(t.TempDir(), "soroauth.1")}, nil, "usage error"},

		{"completions", []string{"completions", "--shell", "bash"}, nil, "success"},
		{"completions without --shell", []string{"completions"}, nil, "usage error"},

		{"doctor with every check passing", []string{"doctor", "--rpc-url", healthy.URL}, nil, "every check passed"},
		{"doctor with an unreachable endpoint", []string{"doctor", "--rpc-url", "http://127.0.0.1:0"}, nil, "check failed"},
		{"doctor with an unknown flag", []string{"doctor", "--no-such-flag"}, nil, "usage error"},

		{"wasm-budget within budget", []string{"wasm-budget", "--out", smallWasm, "--budget", "2048"}, nil, "within budget"},
		{"wasm-budget over budget", []string{"wasm-budget", "--out", largeWasm, "--budget", "2048"}, nil, "over budget"},
		{"wasm-budget with an unknown flag", []string{"wasm-budget", "--no-such-flag"}, nil, "usage error"},

		{"simulate", []string{"simulate", "--entry", unsignedEnvelope, "--rpc-url", rpcOK.server.URL}, nil, "success"},
		{"simulate refused by the host", []string{"simulate", "--entry", unsignedEnvelope, "--rpc-url", rpcHostError.server.URL}, nil, "general error"},
		{"simulate without --entry", []string{"simulate", "--rpc-url", rpcOK.server.URL}, nil, "usage error"},

		{"submit", []string{"submit", "--entry", signedEnvelope, "--network", "testnet", "--secret-env", "SEED", "--rpc-url", rpcOK.server.URL}, payer, "success"},
		{"submit of a transaction that fails on-chain", []string{"submit", "--entry", signedEnvelope, "--network", "testnet", "--secret-env", "SEED", "--rpc-url", rpcTxFailed.server.URL}, payer, "general error"},
		{"submit without --entry", []string{"submit", "--network", "testnet", "--secret-env", "SEED", "--rpc-url", rpcOK.server.URL}, payer, "usage error"},
	}

	produced := map[string]map[int]bool{}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			command := ""
			if len(sc.args) > 0 && !strings.HasPrefix(sc.args[0], "-") {
				command = sc.args[0]
			}
			scope, known := scopeOf[command]
			if !known {
				// An unknown command is the dispatcher's, so the global codes apply.
				scope = globalScope
			}
			got := runCLIProcess(t, configHome, sc.env, "", sc.args...)
			desc, ok := documented[scope][got.code]
			if !ok {
				t.Fatalf("soroauth %s exited %d, which %s does not document (documented: %v)\noutput:\n%s",
					strings.Join(sc.args, " "), got.code, scopeName(scope), sortedCodes(documented[scope]), got.output)
			}
			if !strings.Contains(strings.ToLower(desc), sc.meaning) {
				t.Fatalf("soroauth %s exited %d, documented as %q, but this scenario should produce the code documented as %q\noutput:\n%s",
					strings.Join(sc.args, " "), got.code, desc, sc.meaning, got.output)
			}
			if produced[scope] == nil {
				produced[scope] = map[int]bool{}
			}
			produced[scope][got.code] = true
		})
	}

	// The other direction: every documented code is reachable by a real
	// invocation, so the documentation cannot promise a code the CLI never
	// returns.
	for scope, codes := range documented {
		for _, code := range sortedCodes(codes) {
			if !produced[scope][code] {
				t.Errorf("%s documents exit code %d (%q), but no scenario produced it",
					scopeName(scope), code, codes[code])
			}
		}
	}
}

// scopeName renders a documentation scope for a failure message.
func scopeName(scope string) string {
	if scope == globalScope {
		return "docs/soroauth.1 (EXIT CODES)"
	}
	return "soroauth " + scope + " -h"
}

func sortedCodes(codes map[int]string) []int {
	out := make([]int, 0, len(codes))
	for code := range codes {
		out = append(out, code)
	}
	sort.Ints(out)
	return out
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
