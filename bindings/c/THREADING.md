# libsoroauth threading contract

This is the committed concurrency contract for the C ABI declared in
[libsoroauth.h](libsoroauth.h). Every language binding in this repository
(`bindings/python`, `bindings/jvm`, `bindings/node`) and every third-party
consumer builds against this contract, not an inferred one.

## Summary

Every exported function in `libsoroauth.h` is **safe to call concurrently** from
any thread, including simultaneous calls to the same function. There is no
`SoroauthInit` entry point; no library-wide lock; no per-function serialisation
requirement; and no OS-thread affinity (a call may enter on one thread and
return on another so far as the host is concerned, because Go's scheduler owns
thread assignment, not the caller).

What a correct caller still has to do:

- **Own each returned pointer.** The C string that every non-void function
  returns is caller-owned; release it with `SoroauthFree` exactly once. A double
  free is a bug in the caller; `SoroauthFree(NULL)` is a documented no-op.
- **Keep input strings alive for the call.** The ABI reads `const char*`
  arguments during the call only; it does not retain them. A caller that reuses
  or frees a buffer concurrently with the call racing against its own reader is
  a caller-side race the ABI cannot detect.
- **Not race `SoroauthFree` against a reader of the same pointer.** Freeing a
  string on one thread while another reads it is a C-standard use-after-free; it
  is the caller's responsibility.

## What the library guarantees

The exported surface in `bindings/c/soroauth.go` has **no package-level mutable
state**: every function decodes its inputs into fresh allocations, calls into
`github.com/soroauth/soroauth-go`, and encodes the result into a fresh
`C.CString`. Two concurrent calls share nothing the Go runtime does not already
make safe.

Where the Go core _does_ keep state across calls — a `sync.Pool` for the
marshal/unmarshal buffers (`internal/xdrcopy`), a `sync.Mutex` inside the nonce
tracker, the signer cache, the batch builder and the rate limiter — the state is
explicitly guarded. The race detector check in `make test` and in
`go test -race ./...` in CI runs with that guarding in place, so a regression
there fails the branch's required `vet and test` check.

What this guarantee does not cover:

- **Host-side state the binding adds.** A binding that maintains a cache of
  returned entries, or that shares a `char*` across threads after `SoroauthFree`
  returned it to the allocator, is in caller-side race territory. The
  race-detector run proves the Go side; it cannot prove the JVM or Python side.
- **Signal handlers.** The ABI makes no signal-safety claim. A call from a POSIX
  signal handler is not supported.
- **Signer side effects.** The exported functions in `libsoroauth.h` construct
  their own ed25519 signers in-call. Neither `AccountMultiSigner` nor the
  built-in `Ed25519Signer` holds cross-call mutable state, so two concurrent
  `SoroauthAuthorizeWithSeed` calls that happen to use the same seed sign
  independent payloads independently.

## Evidence

- `threading_abi_test.go` at the repository root exercises the same code path
  every `//export` in `bindings/c/soroauth.go` calls into — `Preimage`,
  `Payload`, `AuthorizeEntry` (single-key and `AccountMultiSigner`), `Inspect`,
  `Analyze`, `InvocationTreeASCII` and `DelegateTreeASCII` — from many
  goroutines over a golden vector set, and passes under `go test -race`.
- The race run is evidence for the **Go side** of the boundary. A caller that
  mishandles a `char*` on the host side is outside what the race detector can
  see; see "What the library guarantees" above.
- `TestCopyConcurrentReuse` in `internal/xdrcopy/copy_test.go` pins the
  no-aliasing property of the marshal/unmarshal buffer pool that every deep-copy
  path in the library stands on.

## Scope relative to issue #518

[#518](https://github.com/soroauth/soroauth-go/issues/518) is a macOS crash in
the host (JVM/Python) when the shared library's stack interacts with the host
thread's stack. The contract this file states, and the test that proves it,
document what the library claims and show that claim holds on the Go side of the
boundary. Fixing #518 — if the fix turns out to narrow this contract — is
tracked separately so the documented contract and the host interaction are not
conflated.
