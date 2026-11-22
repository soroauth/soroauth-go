// Package conformance implements the cross-language conformance suite
// described in testdata/conformance/README.md.
//
// The committed case list is one data file; each binding ships a thin runner
// that reads the file and writes NDJSON to stdout. This package is the Go
// side of that: it defines the case schema, loads the file, and runs cases
// against the native Go library. The output it produces is the baseline
// every other binding's CI job diffs against.
//
// The expected outputs for happy-path cases are derived from the referenced
// golden vector files rather than duplicated in cases.json — one of the
// explicit design decisions of the suite.
package conformance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// SchemaVersion is the schema version this build knows about. A file
// declaring a different version is refused rather than best-effort parsed.
const SchemaVersion = 1

// File is the on-disk cases.json shape.
type File struct {
	SchemaVersion int    `json:"schema_version"`
	Description   string `json:"description,omitempty"`
	Cases         []Case `json:"cases"`
}

// Case is one row in the suite. Exactly one of Vector or Input must be set;
// Override (when present) layers on top of a Vector to tweak one input.
type Case struct {
	ID       string           `json:"id"`
	Op       string           `json:"op"`
	Vector   string           `json:"vector,omitempty"`
	Input    map[string]any   `json:"input,omitempty"`
	Override map[string]any   `json:"override,omitempty"`
	Expect   *ExpectedOutcome `json:"expect,omitempty"`
}

// ExpectedOutcome is the stated outcome for a case that is not a plain
// happy-path case. Happy paths derive their expected outputs from the
// referenced vector.
type ExpectedOutcome struct {
	// OK, when set to a non-nil false, marks an error case.
	OK *bool `json:"ok,omitempty"`
	// KindIn is the set of acceptable kind strings on an error case.
	// Bindings vary on the exact sentinel for a non-library-exported
	// failure; listing more than one keeps the suite honest without pinning
	// one language's choice.
	KindIn []string `json:"kind_in,omitempty"`
}

// Operations the suite knows about. New ops add a row here plus a Run branch.
const (
	OpPreimage          = "preimage"
	OpPayload           = "payload"
	OpAuthorizeWithSeed = "authorize_with_seed"
)

// Result is one NDJSON line a runner emits. It is marshalled by MarshalJSON
// so the on-wire order matches the README's contract.
type Result struct {
	ID             string `json:"id"`
	OK             bool   `json:"ok"`
	PreimageXDR    string `json:"preimage_xdr,omitempty"`
	PayloadHex     string `json:"payload_hex,omitempty"`
	SignedEntryB64 string `json:"signed_entry_xdr,omitempty"`
	Kind           string `json:"kind,omitempty"`
	Error          string `json:"error,omitempty"`
}

// Load reads and validates a cases.json file at path.
func Load(path string) (*File, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("conformance: reading %q: %w", path, err)
	}
	var f File
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("conformance: decoding %q: %w", path, err)
	}
	if f.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("conformance: %q: schema_version %d is unknown (this build reads version %d)", path, f.SchemaVersion, SchemaVersion)
	}
	seen := map[string]int{}
	for i, c := range f.Cases {
		if c.ID == "" {
			return nil, fmt.Errorf("conformance: case %d: id is required", i)
		}
		if prev, ok := seen[c.ID]; ok {
			return nil, fmt.Errorf("conformance: case %q: duplicated at indices %d and %d", c.ID, prev, i)
		}
		seen[c.ID] = i
		if c.Vector == "" && c.Input == nil {
			return nil, fmt.Errorf("conformance: case %q: either vector or input must be set", c.ID)
		}
		if !knownOp(c.Op) {
			return nil, fmt.Errorf("conformance: case %q: unknown op %q", c.ID, c.Op)
		}
	}
	return &f, nil
}

// knownOp reports whether op is one the suite executes.
func knownOp(op string) bool {
	switch op {
	case OpPreimage, OpPayload, OpAuthorizeWithSeed:
		return true
	}
	return false
}

// vectorFile is the subset of a golden vector this suite reads. Fields
// outside this struct are ignored, so the vector format can grow without
// pinning this code to it.
type vectorFile struct {
	Name              string       `json:"name"`
	NetworkPassphrase string       `json:"network_passphrase"`
	ValidUntilLedger  uint32       `json:"valid_until_ledger"`
	UnsignedEntryXDR  string       `json:"unsigned_entry_xdr"`
	PreimageXDR       string       `json:"preimage_xdr"`
	PayloadHex        string       `json:"payload_hex"`
	SignedEntryXDR    string       `json:"signed_entry_xdr"`
	Steps             []vectorStep `json:"steps"`
}

type vectorStep struct {
	SignerLabel string  `json:"signer_label"`
	ForAddress  *string `json:"for_address"`
}

// LoadVector reads a vector by name relative to vectorsDir (usually
// testdata/vectors). A reader that loads cases.json with a relative vector
// name passes the vectors directory alongside.
func LoadVector(vectorsDir, name string) (*vectorFile, error) {
	path := filepath.Join(vectorsDir, name+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("conformance: reading vector %q: %w", name, err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("conformance: decoding vector %q: %w", name, err)
	}
	return &v, nil
}

// Run executes every case in f against the Go oracle and returns one Result
// per case in order. A runner for another binding mirrors this function,
// but calls into its own binding instead of the Go library directly.
func Run(f *File, vectorsDir string) ([]Result, error) {
	out := make([]Result, 0, len(f.Cases))
	for _, c := range f.Cases {
		out = append(out, runCase(c, vectorsDir))
	}
	return out, nil
}

// runCase returns the Result of one case. A failure in the Go library
// becomes an ok:false row with the library's error message; the runner is
// not the place to classify errors (the kind mapping lives in the C ABI
// envelope, not here).
func runCase(c Case, vectorsDir string) Result {
	inputs, err := resolveInputs(c, vectorsDir)
	if err != nil {
		return Result{ID: c.ID, OK: false, Kind: "ERROR", Error: err.Error()}
	}
	switch c.Op {
	case OpPreimage:
		return runPreimage(c.ID, inputs)
	case OpPayload:
		return runPayload(c.ID, inputs)
	case OpAuthorizeWithSeed:
		return runAuthorize(c.ID, inputs)
	default:
		return Result{ID: c.ID, OK: false, Kind: "ERROR", Error: "unknown op " + c.Op}
	}
}

// resolveInputs merges a case's vector-derived inputs with any Input and
// Override maps. The merging order is: vector (base) → Input (full replace)
// → Override (partial patch).
func resolveInputs(c Case, vectorsDir string) (map[string]any, error) {
	inputs := map[string]any{}
	if c.Vector != "" {
		v, err := LoadVector(vectorsDir, c.Vector)
		if err != nil {
			return nil, err
		}
		inputs["entry_xdr_b64"] = v.UnsignedEntryXDR
		inputs["valid_until_ledger"] = float64(v.ValidUntilLedger)
		inputs["network_passphrase"] = v.NetworkPassphrase
		inputs["preimage_xdr_b64"] = v.PreimageXDR
		if len(v.Steps) > 0 {
			seed, err := seedForLabel(v.Steps[0].SignerLabel)
			if err != nil {
				return nil, err
			}
			inputs["seed_hex"] = hex.EncodeToString(seed[:])
		}
	}
	for k, v := range c.Input {
		inputs[k] = v
	}
	for k, v := range c.Override {
		inputs[k] = v
	}
	return inputs, nil
}

// seedForLabel derives the deterministic ed25519 seed each signer_label in
// the golden vectors signs with. The derivation is SHA-256(label); the
// vectors were generated this way, and the signing step in each vector uses
// it so the result is byte-identical.
func seedForLabel(label string) ([32]byte, error) {
	seed := sha256.Sum256([]byte(label))
	if _, err := keypair.FromRawSeed(seed); err != nil {
		return [32]byte{}, err
	}
	return seed, nil
}

// runPreimage performs the preimage op and returns the Result row.
func runPreimage(id string, inputs map[string]any) Result {
	entryB64, _ := inputs["entry_xdr_b64"].(string)
	validUntil, _ := inputs["valid_until_ledger"].(float64)
	passphrase, _ := inputs["network_passphrase"].(string)

	entry, err := decodeEntry(entryB64)
	if err != nil {
		return Result{ID: id, OK: false, Kind: "ERROR", Error: err.Error()}
	}
	if passphrase == "" {
		return Result{ID: id, OK: false, Kind: "ERROR", Error: "network passphrase is required"}
	}
	preimage, err := soroauth.Preimage(entry, uint32(validUntil), passphrase)
	if err != nil {
		return Result{ID: id, OK: false, Kind: "ERROR", Error: err.Error()}
	}
	raw, err := preimage.MarshalBinary()
	if err != nil {
		return Result{ID: id, OK: false, Kind: "ERROR", Error: err.Error()}
	}
	payload, err := soroauth.Payload(preimage)
	if err != nil {
		return Result{ID: id, OK: false, Kind: "ERROR", Error: err.Error()}
	}
	return Result{
		ID:          id,
		OK:          true,
		PreimageXDR: base64.StdEncoding.EncodeToString(raw),
		PayloadHex:  hex.EncodeToString(payload[:]),
	}
}

// runPayload performs the payload op and returns the Result row.
//
// decode-allow: the base64 blob is a HashIdPreimage the case supplies, and
// soroauth publishes no bounded decoder for that type.
func runPayload(id string, inputs map[string]any) Result {
	preimageB64, _ := inputs["preimage_xdr_b64"].(string)
	var preimage xdr.HashIdPreimage
	if err := xdr.SafeUnmarshalBase64(preimageB64, &preimage); err != nil {
		return Result{ID: id, OK: false, Kind: "ERROR", Error: err.Error()}
	}
	payload, err := soroauth.Payload(preimage)
	if err != nil {
		return Result{ID: id, OK: false, Kind: "ERROR", Error: err.Error()}
	}
	return Result{
		ID:         id,
		OK:         true,
		PayloadHex: hex.EncodeToString(payload[:]),
	}
}

// runAuthorize performs the authorize_with_seed op and returns the Result
// row.
func runAuthorize(id string, inputs map[string]any) Result {
	entryB64, _ := inputs["entry_xdr_b64"].(string)
	validUntil, _ := inputs["valid_until_ledger"].(float64)
	passphrase, _ := inputs["network_passphrase"].(string)
	seedHex, _ := inputs["seed_hex"].(string)
	forAddress, _ := inputs["for_address"].(string)

	entry, err := decodeEntry(entryB64)
	if err != nil {
		return Result{ID: id, OK: false, Kind: "ERROR", Error: err.Error()}
	}
	kp, err := decodeSeed(seedHex)
	if err != nil {
		return Result{ID: id, OK: false, Kind: "ERROR", Error: err.Error()}
	}

	opts := []soroauth.AuthorizeOption{}
	if forAddress != "" {
		opts = append(opts, soroauth.ForAddress(forAddress))
	}
	signed, err := soroauth.AuthorizeEntry(context.Background(), entry, soroauth.NewEd25519Signer(kp), uint32(validUntil), passphrase, opts...)
	if err != nil {
		return Result{ID: id, OK: false, Kind: "ERROR", Error: err.Error()}
	}
	encoded, err := xdr.MarshalBase64(signed)
	if err != nil {
		return Result{ID: id, OK: false, Kind: "ERROR", Error: err.Error()}
	}
	return Result{
		ID:             id,
		OK:             true,
		SignedEntryB64: encoded,
	}
}

// decodeEntry reads an entry from a base64 string with the library's
// bounded decoder.
func decodeEntry(entryB64 string) (xdr.SorobanAuthorizationEntry, error) {
	if entryB64 == "" {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("entry is empty")
	}
	return soroauth.DecodeAuthorizationEntry(entryB64)
}

// decodeSeed parses a 32-byte ed25519 seed given as hex and returns its
// keypair.
func decodeSeed(seedHex string) (*keypair.Full, error) {
	b, err := hex.DecodeString(strings.TrimSpace(seedHex))
	if err != nil {
		return nil, fmt.Errorf("decoding seed: %w", err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("seed must be 32 bytes, got %d", len(b))
	}
	var seed [32]byte
	copy(seed[:], b)
	kp, err := keypair.FromRawSeed(seed)
	if err != nil {
		return nil, fmt.Errorf("deriving keypair: %w", err)
	}
	return kp, nil
}

// Diff compares actual against expected and returns the ids of cases that
// disagree, along with a human-readable summary line per failure. A runner's
// CI job calls this (or re-implements it in its own language) and exits
// non-zero when the return is non-empty.
func Diff(f *File, vectorsDir string, actual []Result) ([]string, error) {
	if len(actual) != len(f.Cases) {
		return nil, fmt.Errorf("conformance: got %d result rows, want %d", len(actual), len(f.Cases))
	}
	var fails []string
	for i, c := range f.Cases {
		got := actual[i]
		if got.ID != c.ID {
			fails = append(fails, fmt.Sprintf("row %d: id = %q, want %q", i, got.ID, c.ID))
			continue
		}
		if err := compareOne(c, got, vectorsDir); err != nil {
			fails = append(fails, fmt.Sprintf("case %s: %v", c.ID, err))
		}
	}
	return fails, nil
}

// compareOne is the per-case comparison Diff iterates over.
func compareOne(c Case, got Result, vectorsDir string) error {
	// Error case expectations.
	if c.Expect != nil && c.Expect.OK != nil && !*c.Expect.OK {
		if got.OK {
			return fmt.Errorf("want error, got ok=true")
		}
		if len(c.Expect.KindIn) == 0 {
			return nil
		}
		for _, k := range c.Expect.KindIn {
			if got.Kind == k {
				return nil
			}
		}
		return fmt.Errorf("kind %q is not in the allowed set %v", got.Kind, c.Expect.KindIn)
	}

	// Happy path: expected output comes from the referenced vector.
	if !got.OK {
		return fmt.Errorf("want ok, got error: kind=%s error=%s", got.Kind, got.Error)
	}
	if c.Vector == "" {
		// Happy path without a vector is only meaningful if the runner
		// records something comparable; the case author should add a
		// vector or an explicit expect.
		return nil
	}
	v, err := LoadVector(vectorsDir, c.Vector)
	if err != nil {
		return err
	}
	switch c.Op {
	case OpPreimage:
		if got.PreimageXDR != v.PreimageXDR {
			return fmt.Errorf("preimage_xdr mismatch")
		}
		if got.PayloadHex != v.PayloadHex {
			return fmt.Errorf("payload_hex mismatch: got %s, want %s", got.PayloadHex, v.PayloadHex)
		}
	case OpPayload:
		if got.PayloadHex != v.PayloadHex {
			return fmt.Errorf("payload_hex mismatch: got %s, want %s", got.PayloadHex, v.PayloadHex)
		}
	case OpAuthorizeWithSeed:
		if got.SignedEntryB64 != v.SignedEntryXDR {
			return fmt.Errorf("signed_entry_xdr mismatch")
		}
	}
	return nil
}
