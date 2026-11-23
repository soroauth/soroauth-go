//go:build js && wasm

// Command soroauthwasm compiles the soroauth signing core to WebAssembly and
// exposes it to JavaScript on globalThis.soroauth.
//
// Rationale for the exported API surface:
//   - preimage: derives the signing HashIdPreimage and its 32-byte SHA-256 payload
//     locally in the browser, eliminating reliance on a trusted server.
//   - payload: hashes an already constructed preimage (base64 XDR) to its 32-byte
//     digest, supporting remote signers without entry reconstruction.
//   - writeSignature: writes an externally produced signature ScVal onto target
//     credential nodes, maintaining strict isolation of signing keys.
//   - authorizeWithSeed: provides a deterministic test and local demo path using
//     an in-memory raw ed25519 seed.
//   - passkeySignature: builds the {public_key, signature} ScVal a passkey
//     wallet contract decodes, so an offline page needs no second XDR encoder.
//
// Why this exists: passkey signing happens in the browser, and the browser
// should derive the bytes it signs rather than trust a server to hand them
// over. This binary is the smallest surface that makes that possible -- build a
// preimage, hash it to a payload, and write an externally produced signature
// back onto an entry. It is not a second implementation: the body of every
// function lives in internal/wasmcore, which the WASI target calls too, so the
// bytes cannot drift between targets or from the native library.
//
// The whole package is behind `//go:build js && wasm`, so it is not compiled
// for any other target and `go build ./...` skips it on the host. CI builds it
// for js/wasm explicitly (see the wasm job in .github/workflows/ci-wasm.yml).
//
// Calling convention: every exported function returns an object
//
//	{ "ok": true,  ...result fields }        on success
//	{ "ok": false, "error": "message" }      on failure
//
// The TypeScript wrapper in wasm/ts turns a false `ok` into a thrown Error so
// callers never have to branch on a numeric code.
package main

import (
	"fmt"
	"syscall/js"

	"github.com/soroauth/soroauth-go/internal/wasmcore"
)

func main() {
	// Hold the js.Func values in a package-level slice: a js.Func that is only
	// reachable through the JS object can still be collected, and a collected
	// callback makes the next JS call fail with "invalid callback".
	functions := []js.Func{
		js.FuncOf(preimage),
		js.FuncOf(payload),
		js.FuncOf(writeSignature),
		js.FuncOf(authorizeWithSeed),
		js.FuncOf(passkeySignature),
	}
	bindings = functions

	js.Global().Set("soroauth", js.ValueOf(map[string]any{
		"preimage":          functions[0],
		"payload":           functions[1],
		"writeSignature":    functions[2],
		"authorizeWithSeed": functions[3],
		"passkeySignature":  functions[4],
	}))

	// Keep the program alive so the callbacks remain callable from JS.
	select {}
}

// bindings keeps every exported js.Func reachable for the lifetime of the
// program.
var bindings []js.Func

// ok builds the success envelope.
func ok(fields map[string]any) map[string]any {
	out := map[string]any{"ok": true}
	for k, v := range fields {
		out[k] = v
	}
	return out
}

// fail builds the failure envelope. The message is the wrapped library error,
// which already names the operation, so the caller sees exactly what failed.
func fail(err error) map[string]any {
	return map[string]any{"ok": false, "error": err.Error()}
}

// preimage(entryB64, validUntilLedger, networkPassphrase) ->
//
//	{ok, preimageXdr, payloadHex} | {ok:false, error}
func preimage(this js.Value, args []js.Value) any {
	if len(args) != 3 {
		return fail(fmt.Errorf("soroauth: wasm: preimage expects 3 arguments"))
	}
	result, err := wasmcore.Preimage(args[0].String(), uint32(args[1].Int()), args[2].String())
	if err != nil {
		return fail(err)
	}
	return ok(map[string]any{
		"preimageXdr": result.PreimageXDR,
		"payloadHex":  result.PayloadHex,
	})
}

// payload(preimageXdrBase64) -> {ok, payloadHex} | {ok:false, error}
func payload(this js.Value, args []js.Value) any {
	if len(args) != 1 {
		return fail(fmt.Errorf("soroauth: wasm: payload expects 1 argument"))
	}
	digest, err := wasmcore.Payload(args[0].String())
	if err != nil {
		return fail(err)
	}
	return ok(map[string]any{"payloadHex": digest})
}

// writeSignature(entryB64, validUntilLedger, networkPassphrase, forAddress,
// signatureScvalB64) -> {ok, entryB64} | {ok:false, error}
//
// This is the browser path: the signature bytes are produced elsewhere (a
// passkey, a remote signer) and this writes the produced ScVal onto every node
// whose address matches. An empty forAddress means "the entry's own
// top-level address".
func writeSignature(this js.Value, args []js.Value) any {
	if len(args) != 5 {
		return fail(fmt.Errorf("soroauth: wasm: writeSignature expects 5 arguments"))
	}
	encoded, err := wasmcore.WriteSignature(
		args[0].String(), uint32(args[1].Int()), args[2].String(),
		args[3].String(), args[4].String(),
	)
	if err != nil {
		return fail(err)
	}
	return ok(map[string]any{"entryB64": encoded})
}

// authorizeWithSeed(entryB64, validUntilLedger, networkPassphrase, seedHex,
// forAddress) -> {ok, entryB64} | {ok:false, error}
//
// A convenience path for deterministic signers (conformance tests, and browser
// demos that hold a raw key in memory). It derives an ed25519 key from a raw
// 32-byte seed and signs exactly as the native library does.
func authorizeWithSeed(this js.Value, args []js.Value) any {
	if len(args) != 5 {
		return fail(fmt.Errorf("soroauth: wasm: authorizeWithSeed expects 5 arguments"))
	}
	encoded, err := wasmcore.AuthorizeWithSeed(
		args[0].String(), uint32(args[1].Int()), args[2].String(),
		args[3].String(), args[4].String(),
	)
	if err != nil {
		return fail(err)
	}
	return ok(map[string]any{"entryB64": encoded})
}

// passkeySignature(publicKeyHex, signatureHex) ->
//
//	{ok, signatureScvalB64} | {ok:false, error}
//
// The body lives in wasmcore with the rest of the signing flow, so the js/wasm
// and WASI targets cannot diverge.
func passkeySignature(this js.Value, args []js.Value) any {
	if len(args) != 2 {
		return fail(fmt.Errorf("soroauth: wasm: passkeySignature expects 2 arguments"))
	}
	encoded, err := wasmcore.PasskeySignature(args[0].String(), args[1].String())
	if err != nil {
		return fail(err)
	}
	return ok(map[string]any{"signatureScvalB64": encoded})
}
