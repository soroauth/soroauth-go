# @soroauth/node

The soroauth signing core as a native Node binding, over the C ABI
(`bindings/c`). For Node backends that cannot run the wasm build.

```js
const { load } = require("@soroauth/node");

const soroauth = load();

const { preimageXdr, payloadHex } = soroauth.preimage(
  unsignedEntryB64,
  validUntilLedger,
  networkPassphrase,
);

// Hand payloadHex to a remote signer, then write its ScVal back:
const signed = soroauth.writeSignature(
  unsignedEntryB64,
  validUntilLedger,
  networkPassphrase,
  "",            // "" means the entry's own top-level address
  signatureScvalB64,
);

console.log(soroauth.inspect(signed));
```

## Platform Support

- **Operating systems**: Linux and macOS. Windows is not supported.
- **Architectures**: `x86_64`, `aarch64` / `arm64`.
- **Runtime**: Node.js 18 or later.

## Threading

Node calls the C ABI from its worker threads through N-API, so the ABI's
contract applies unchanged: every function is safe to call concurrently from any
thread; the addon releases each returned pointer before handing JavaScript its
value, so the host never owns a `char*`. The committed contract lives at
[bindings/c/THREADING.md](../c/THREADING.md).

## Which package to use

|                                    | `@soroauth/node`             | `@soroauth/wasm`                 |
| ---------------------------------- | ---------------------------- | -------------------------------- |
| Target                             | Node backends                | Browsers                         |
| Startup                            | dlopen + one hop             | Go runtime, ~6 MB to instantiate |
| Signing keys in the caller         | yes                          | yes                              |
| Exact same bytes as the Go library | yes, that is the whole point | yes                              |

Use this one on a server. The wasm package stays for the browser, where loading
a native binary is not possible at all.

## Install

Published packages carry a prebuilt pair per platform under
`prebuilds/<os>-<arch>/` (the Go shared library and the N-API addon), so a plain
`npm install` needs no toolchain.

From a checkout of the repository, build it yourself:

```sh
cd bindings/node
npm install        # postinstall attempts the build when no prebuild is present
npm test           # replays every golden vector through this binding
```

A source build needs the Go toolchain (for the shared library, via
`bindings/c/build.sh`) and a C toolchain plus `node-gyp` (for the addon). If
either is missing, the install still succeeds and every call throws a
`SoroauthError` naming the missing artifact — a binding that is not there must
never look like one that signed something.

## Prebuilds

| OS    | Architecture    | Node               |
| ----- | --------------- | ------------------ |
| Linux | x86_64, aarch64 | 22, 24 (see below) |
| macOS | arm64, x86_64   | 22, 24 (see below) |

The addon is N-API (`node_api.h`), whose ABI is stable across Node versions:
that is why one binary can serve every supported Node rather than one per
version. CI builds and tests the pair on each row of the matrix
(`.github/workflows/ci-node.yml`) and uploads each platform's `prebuilds/`
directory as an artifact; the release workflow assembles them into the published
tarball.

The source build additionally needs `node-gyp`'s own Node floor (^22.22.2 ||
^24.15.0 || >=26 at the version pinned in `devDependencies`).

Windows is not supported: the binding loads the Go shared library with `dlopen`
and this repository builds `c-shared` only for Linux and macOS.

## API

Every call takes and returns base64 XDR strings; `load()` throws if the binding
is not built, and a failed call throws a subclass of `SoroauthError` chosen from
the Go sentinel the failure wraps (`MissingSigner`, `AlreadySigned`,
`TooManySignatures`, `SourceAccountCredentials`, `NoMatchingCredentialNode`, …).
That distinction is deliberate — "no signer for this address" and "unsupported
credentials arm" are different facts, and flattening them into one `Error` would
lose them at the language boundary.

- `preimage(entry, validUntilLedger, networkPassphrase)` — the `HashIdPreimage`
  and its 32-byte payload. Refuses the source-account arm, which has no payload.
- `payload(preimageXdr)` — the payload of an already-built preimage, for a
  remote signer that only ever sees the preimage.
- `writeSignature(entry, validUntilLedger, networkPassphrase, forAddress, signatureScval)`
  — writes an externally produced signature ScVal onto every node whose address
  matches (`""` means the entry's own address). This is the production path: the
  key never enters this process.
- `authorizeWithSeed(entry, validUntilLedger, networkPassphrase, seedHex, forAddress)`
  — signs with a 32-byte ed25519 seed. Deterministic, for tests and tooling.
- `authorizeWithSeeds(entry, …, seedsCsv, forAddress)` — one or more seeds,
  comma-separated. Two or more build an `AccountMultiSigner`: signatures sorted
  strictly ascending by public key, at most the host's 20.
- `inspect(entry)` — the credential arm, address, nonce, expiration, delegate
  tree and invocation tree. Structural only: it does not interpret what a
  contract call will do.
- `analyze(entry, currentLedger?)` — the risk analyzer's findings, with the
  limits documented in
  [`docs/analyzer-heuristics.md`](../../docs/analyzer-heuristics.md).
  Heuristics, not a safety verdict.
- `renderInvocations(entry)`, `renderTree(entry)` — the library's own ASCII
  renderings.

## Verification

`npm test` replays **every** committed golden vector through this binding and
compares the preimage, the payload and the final signed entry to the JS
reference implementation's recorded bytes. That replay is the gate: a binding
that can disagree with the Go library is worse than none, and the only way to
know it does not is to check the bytes.

## Known limitations

### macOS thread-safety under `node:test`

The Go shared library's cgo runtime caches per-thread state (the M's g0 stack
bounds) from the first cgo entry on a given thread. When `node:test` runs tests
across worker threads, Go can be re-entered on a different thread with stale
bounds, triggering `fatal error: morestack on g0`.

The addon serialises every call to the Go library through a pthread mutex, which
prevents the concurrent-entry race that surfaces the stale bounds. This makes
the binding safe under `node:test`, but means calls are not concurrent — which
is consistent with the binding's design (all N-API callbacks are synchronous and
run on the main thread in normal use).

If you observe the crash in an environment this fix does not cover, please
report it. See [golang/go#59294](https://github.com/golang/go/issues/59294) and
[golang/go#31683](https://github.com/golang/go/issues/31683) for the upstream
mechanism.

## License

Apache-2.0. Unaudited; see [`SECURITY.md`](../../SECURITY.md).
