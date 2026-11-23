// Command soroauthwasi exposes the soroauth signing core to a WebAssembly
// System Interface (WASI) host, so the core can run in a sandboxed runtime with
// no JavaScript engine.
//
// The protocol is one JSON request on stdin and one JSON response on stdout for
// the life of the process:
//
//	{"op":"preimage","entry":"<base64>","validUntilLedger":123,
//	 "networkPassphrase":"Test SDF Network ; September 2015"}
//
//	{"ok":true,"preimageXdr":"<base64>","payloadHex":"<hex>"}
//
// A failure is {"ok":false,"error":"..."} with exit status 0, matching the
// js/wasm envelope: the caller always has a result to parse, and a malformed
// request is a reported failure rather than a crash.
//
// Host capabilities: stdin and stdout only. There is no filesystem access, no
// network access and no environment read. The body of every operation lives in
// internal/wasmcore, the same package the js/wasm target calls, so the bytes
// cannot drift between the two targets.
//
// The accepted ops are exactly the js/wasm bindings:
//
//	preimage          entry, validUntilLedger, networkPassphrase
//	payload           preimage
//	writeSignature    entry, validUntilLedger, networkPassphrase, forAddress, signature
//	authorizeWithSeed entry, validUntilLedger, networkPassphrase, seedHex, forAddress
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/soroauth/soroauth-go/internal/wasmcore"
)

// request is one operation. Only the fields the operation names are required;
// the rest default to zero values.
type request struct {
	Op                string `json:"op"`
	Entry             string `json:"entry"`
	ValidUntilLedger  uint32 `json:"validUntilLedger"`
	NetworkPassphrase string `json:"networkPassphrase"`
	Preimage          string `json:"preimage"`
	ForAddress        string `json:"forAddress"`
	Signature         string `json:"signature"`
	SeedHex           string `json:"seedHex"`
}

func main() {
	os.Exit(run(os.Stdin, os.Stdout))
}

// run reads one request, writes one response and returns the process exit
// status. It returns 0 for every reported failure, including a malformed
// request: the response envelope is the error channel. Only a failure to write
// the response is an exit status of 1, because then nothing can be reported.
func run(stdin io.Reader, stdout io.Writer) int {
	body, err := io.ReadAll(stdin)
	if err != nil {
		return write(stdout, failure(fmt.Errorf("soroauth: wasi: reading request: %w", err)))
	}

	var req request
	if err := json.Unmarshal(body, &req); err != nil {
		return write(stdout, failure(fmt.Errorf("soroauth: wasi: decoding request: %w", err)))
	}

	response, err := dispatch(req)
	if err != nil {
		return write(stdout, failure(err))
	}
	return write(stdout, response)
}

// dispatch runs one operation and returns its success envelope.
func dispatch(req request) (map[string]any, error) {
	switch req.Op {
	case "preimage":
		result, err := wasmcore.Preimage(req.Entry, req.ValidUntilLedger, req.NetworkPassphrase)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"ok":          true,
			"preimageXdr": result.PreimageXDR,
			"payloadHex":  result.PayloadHex,
		}, nil

	case "payload":
		digest, err := wasmcore.Payload(req.Preimage)
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "payloadHex": digest}, nil

	case "writeSignature":
		encoded, err := wasmcore.WriteSignature(
			req.Entry, req.ValidUntilLedger, req.NetworkPassphrase, req.ForAddress, req.Signature,
		)
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "entryB64": encoded}, nil

	case "authorizeWithSeed":
		encoded, err := wasmcore.AuthorizeWithSeed(
			req.Entry, req.ValidUntilLedger, req.NetworkPassphrase, req.SeedHex, req.ForAddress,
		)
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "entryB64": encoded}, nil

	default:
		return nil, fmt.Errorf("soroauth: wasi: unknown op %q", req.Op)
	}
}

// failure is the error envelope both targets use.
func failure(err error) map[string]any {
	return map[string]any{"ok": false, "error": err.Error()}
}

// write encodes one response and returns the exit status: 0 on success, 1 when
// the response could not be written.
func write(out io.Writer, response map[string]any) int {
	if err := json.NewEncoder(out).Encode(response); err != nil {
		fmt.Fprintf(os.Stderr, "soroauth: wasi: writing response: %v\n", err)
		return 1
	}
	return 0
}
