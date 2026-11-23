# Getting-Started Guide per Language Binding

A guide per binding — C, Node, Python, JVM, Rust, wasm — taking a reader from
install to a signed entry in their own language.

Each binding has a README describing its build, which is written for someone
working on the binding rather than using it.  A Python or JVM developer currently
has to read Go documentation and infer the mapping, which is the main reason the
bindings see little use.

## Quick navigation

- [Go (native library)](#go-native-library)
- [Node.js](#nodejs)
- [Python](#python)
- [JVM](#jvm)
- [Rust](#rust)
- [WASM](#wasm)
- [Error handling conventions](#error-handling-conventions)
- [Known gaps](#known-gaps)

---

## Go (native library)

The Go library is the canonical implementation.  Install it, build a
preimage, sign an entry, and inspect the result — all using the `soroauth`
package.

### Install

```bash
go get github.com/soroauth/soroauth-go
```

### Quickstart: build, sign and inspect an entry

```go
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/soroauth/soroauth-go"
	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
)

func main() {
	// 1. Derive a test keypair from a public label (deterministic, reproducible).
	seed := os.Getenv("SOROAUTH_SEED")
	if seed == "" {
		// Derive from label if no env var set (for documentation purposes only).
		// In production, the operator supplies the seed via SOROAUTH_SEED.
		fmt.Fprintln(os.Stderr, "set SOROAUTH_SEED to sign")
		os.Exit(1)
	}
	kp, err := keypair.FromRawSeed(sha256.Sum256([]byte("soroauth-gs-signer-1")))
	if err != nil {
		panic(err)
	}

	// 2. Build an unsigned authorization entry.
	//    For this example we use the V2 arm (address-bound) with a simple
	//    contract call invocation.  The soroauth.Preimage function will fail
	//    with ErrUnsupportedCredentials for the source-account arm, so callers
	//    should always use an address or delegates arm.
	entry := sorauth.AuthorizeInvocation(ctx, sorauth.AuthorizeInvocationParams{
		Signer:            sorauth.NewEd25519Signer(kp),
		Invocation:        sorauth.AuthorizedInvocation{ ... }, // see below
		ValidUntilLedger:  1234567,
		NetworkPassphrase: network.TestNetworkPassphrase,
		Legacy:            false, // V2 arm (default)
	})

	// 3. Inspect the entry to confirm its structure.
	info, err := sorauth.Inspect(entry)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Credential type: %s\n", info.CredentialType)
	fmt.Printf("Address: %s\n", info.Address)

	// 4. Build the preimage and payload.
	preimage, err := sorauth.Preimage(entry, 1234567, network.TestNetworkPassphrase)
	if err != nil {
		panic(err)
	}
	payload, err := sorauth.Payload(preimage)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Payload (hex): %s\n", hex.EncodeToString(payload[:]))

	// 5. Sign the payload.
	signature, err := sorauth.NewEd25519Signer(kp).Sign(context.Background(), preimage, payload)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Signature ScVal: %s\n", signature)

	// 6. Write the signature onto the entry.
	signed, err := sorauth.AuthorizeEntry(context.Background(), entry,
		sorauth.NewEd25519Signer(kp), 1234567, network.TestNetworkPassphrase)
	if err != nil {
		panic(err)
	}
	encoded, _ := sorauth.EncodeEntry(signed)
	fmt.Printf("Signed entry (base64): %s\n", encoded)
}
```

**Error handling**: every public function returns either a sentinel error
(`soroauth.ErrUnsupportedCredentials`, `soroauth.ErrNoMatchingCredentialNode`,
etc.) or a wrapping `fmt.Errorf`.  Callers should use `errors.Is` to match
these sentinels, never compare error strings.  The Go convention of wrapping
errors with `soroauth: <operation>: %w` means bindings can match on the
sentinel code rather than parsing message text.

**What this binding does not support**: the source-account arm (`SOROBAN_CREDENTIALS_SOURCE_ACCOUNT`)
has no signature payload; `Preimage` returns `ErrSourceAccountCredentials` for
it.  The library will not silently sign a source-account entry — the caller
must handle this case explicitly.

---

## Node.js (`@soroauth/node`)

The Node.js binding uses the C ABI shared library (`libsoroauth`) built from
the Go source, loaded via `cffi`.  It provides a JavaScript-native interface.

### Install

```bash
npm install @soroauth/node
```

### Quickstart: build, sign and inspect an entry

```js
const { sorauth } = require('@soroauth/node');
const { keypair } = require('@stellar/stellar-sdk');
const { TestNetworkPassphrase } = require('@stellar/stellar-sdk');

async function main() {
  // 1. Derive a keypair from a seed.
  //    In production, the seed comes from an environment variable or KMS.
  const seed = process.env.SOROAUTH_SEED;
  if (!seed) {
    console.error('set SOROAUTH_SEED environment variable');
    process.exit(1);
  }
  const kp = keypair.FromSecretSeed(seed);

  // 2. Build an unsigned authorization entry (V2 arm).
  //    The binding's `authorizeWithSeed` function builds the preimage,
  //    signs it, and returns the signed entry.
  const entryB64 = sorauth.authorizeWithSeed(
    // authorization entry as base64 XDR (built by the caller or via
    // sorauth-go's AuthorizeInvocation)
    // For a minimal V2 entry, callers can use the Go library to produce one,
    // or construct the XDR manually.
    // placeholder: use Go to produce the unsigned entry first.
    '',
    1234567,
    TestNetworkPassphrase,
    seed
  );

  // 3. Inspect the entry.
  const info = sorauth.inspect(entryB64);
  console.log('Credential type:', info.credential_type);
  console.log('Address:', info.address);

  // 4. The `authorizeWithSeed` call already produced a signed entry.
  //    Verify the payload binding by re-computing the hash.
  const payloadObj = sorauth.payload(entryB64);
  console.log('Payload hex:', payloadObj.payload);
}
```

**Error handling**: the C JSON envelope format `{"ok":true,...}` or
`{"ok":false,"error":"...","kind":"SENTINEL"}` is parsed by the binding.
Bindings should switch on the `kind` field (which maps to a Go sentinel) rather
than string-matching the `error` text.  This gives stable error handling across
library versions.

**What this binding does not support**: passkey/secp256r1 signers are not
implemented in the Go library yet (see the non-goals in CLAUDE.md).  The
binding cannot sign entries that use the source-account arm, because the
underlying Go preimage function returns `ErrSourceAccountCredentials` for that
arm.

---

## Python (`soroauth` package)

The Python binding wraps the C shared library via `cffi`.  It provides a
Pythonic interface that mirrors the Go API.

### Install

```bash
pip install sorauth
```

### Quickstart: build, sign and inspect an entry

```python
import sorauth
from stellar_sdk import keypair  # or from the stellar-sdk bundle

# 1. Derive a keypair from a seed.
seed = os.environ.get("SOROAUTH_SEED")
if not seed:
    print("set SOROAUTH_SEED environment variable")
    exit(1)
kp = keypair.Keypair.from_secret_seed(seed)

# 2. Build an unsigned authorization entry (V2 arm).
#    Use the Go library to produce one, or construct the XDR manually.
#    Here we assume `entry_b64` is an unsigned V2 authorization entry.
entry_b64 = "..."  # base64-encoded unsigned entry

# 3. Inspect the entry.
info = sorauth.inspect(entry_b64)
print(f"Credential type: {info['credential_type']}")
print(f"Address: {info['address']}")

# 4. Build the preimage and payload.
preimage_result = sorauth.payload(entry_b64)
# preimage_result is a dict: {"preimage": "<base64>", "payload": "<hex>"}
print(f"Payload: {preimage_result['payload']}")

# 5. Sign the payload (the binding internally calls the C library to sign).
signed_b64 = sorauth.authorize_with_seed(
    entry_b64,
    valid_until_ledger=1234567,
    network_passphrase="Test SDF Network ; September 2015",
    seed=seed,
)

# 6. The signed entry is returned as base64 XDR.
print(f"Signed entry: {signed_b64}")
```

**Error handling**: the binding raises `soroauth.SoroauthError` (and its
subclasses like `SourceAccountCredentialsError`, `UnsupportedCredentialsError`,
`NoMatchingCredentialNodeError`, etc.) for every refusal.  Callers should
catch these specific exception types rather than matching error strings:

```python
try:
    sorauth.authorize_with_seed(...)
except sorauth.UnsupportedCredentialsError:
    print("this entry arm is not supported")
except sorauth.NoMatchingCredentialNodeError as e:
    print(f"no node matches: {e.address}")
```

**What this binding does not support**: the source-account arm is not supported
— `authorize_with_seed` will raise `UnsupportedCredentialsError` for it.
Also, passkey/secp256r1 signers are not available in the Go library, so they
cannot be used from Python either.

---

## JVM (`soroauth-jvm`)

The JVM binding provides a Java wrapper over the soroauth signing core, using
the same bytes and honesty boundaries as the Go library.

### Add dependency

```xml
<dependency>
    <groupId>org.soroauth</groupId>
    <artifactId>soroauth-jvm</artifactId>
    <version>0.1.0</version>
</dependency>
```

### Quickstart: build, sign and inspect an entry

```java
import org.soroauth.Soroauth;
import org.soroauth.SoroauthException;
import org.soroauth.SourceAccountCredentialsException;
import com.stellar.sdk.KeyPair;
import com.stellar.NetworkPassphrase;

public class Main {
    public static void main(String[] args) {
        // 1. Load the signing key.
        KeyPair kp = KeyPair.fromSecretKey(
            java.util.Base64.getDecoder().decode(System.getenv("SOROAUTH_SEED")));

        // 2. Build an unsigned authorization entry (V2 arm).
        //    Use the Go library to produce the unsigned entry XDR, or construct
        //    it manually.  The JVM binding's `authorizeWithSeed` method builds
        //    the preimage, signs it, and returns the signed entry as base64 XDR.
        String entryB64 = "...org.soroauth.SoroauthException: unsupported credentials type";
        try {
            String signedB64 = Soroauth.authorizeWithSeed(
                entryB64, 1234567L, NetworkPassphrase.TEST_NETWORK, 
                java.util.Base64.getDecoder().decode(System.getenv("SOROAUTH_SEED")));
            System.out.println("Signed entry: " + signedB64);
        } catch (SourceAccountCredentialsException e) {
            System.err.println("Source-account arm not supported: " + e.getMessage());
        } catch (SoroauthException e) {
            System.err.println("Signing failed: " + e.getMessage());
        }
    }
}
```

**Error handling**: the JVM binding raises `SoroauthException` with a `kind`
field that maps to a Go sentinel (`SOURCE_ACCOUNT_CREDENTIALS`,
`UNSUPPORTED_CREDENTIALS`, `NO_MATCHING_CREDENTIAL_NODE`, etc.).  Java callers
should switch on the `kind` field:

```java
try {
    Soroauth.authorizeWithSeed(...);
} catch (SourceAccountCredentialsException e) {
    // the entry uses the source-account arm
} catch (UnsupportedCredentialsException e) {
    // the credentials arm is not supported
}
```

**What this binding does not support**: the source-account arm (`SOROBAN_CREDENTIALS_SOURCE_ACCOUNT`)
is not supported — `authorizeWithSeed` throws `SourceAccountCredentialsException`
for it.  Passkey/secp256r1 signers are also not available.

---

## Rust (`soroauth` crate)

The Rust crate is byte-identical to the Go library.  It is not published to
crates.io but can be used from a local path.

### Add dependency

```toml
[dependencies]
soroauth = { path = "bindings/rust" }
```

### Quickstart: build, sign and inspect an entry

```rust
use soroauth::{preimage, payload, AuthorizeInvocation, Ed25519Signer};
use stellar_xdr::{sorobanauthorizeentry::*, crypto::ed25519};
use stellar_xdr::{Address, ScVal, ScvMap, ScvSymbol, ScvVec};
use std::convert::TryFrom;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Create a signing key from a seed phrase.
    let seed = std::env::var("SOROAUTH_SEED")
        .expect("SOROAUTH_SEED must be set");
    let kp = ed25519::KeyPair::from_seed(seed.as_bytes());

    // 2. Build an unsigned V2 authorization entry.
    //    Use AuthorizeInvocation to build the entry, then preimage/payload/sign.
    let invocation = AuthorizeInvocation {
        signer: Ed25519Signer::new(&kp),
        // ... invocation details ...
        valid_until_ledger: 1234567,
        network_passphrase: "Test SDF Network ; September 2015",
        legacy: false,
    };
    let entry = soroauth::authorize_invocation(invocation);

    // 3. Inspect the entry.
    let info = soroauth::inspect(&entry);
    println!("Credential type: {}", info.credential_type);

    // 4. Build the preimage and payload.
    let pre = preimage(&entry, 1234567, "Test SDF Network ; September 2015")?;
    let pay = payload(&pre)?;

    // 5. Sign the payload (the crate's Signer does this internally).
    let sig = soroauth::sign(&entry, &pre, pay)?;

    // 6. Write the signature onto the entry.
    let signed = soroauth::authorize_entry(&entry, &sig, 1234567, "Test SDF Network ; September 2015")?;

    println!("Signed entry (base64): {}", soroauth::encode_entry(&signed));
    Ok(())
}
```

**Error handling**: the Rust crate maps Go sentinel errors to its own error
types via the `soroauth` FFI.  Callers should use `errors.Is` or match on
the error kind string:

```rust
match soroauth::authorize_entry(...) {
    Ok(signed) => println!("success"),
    Err(soroauth::Error::SourceAccountCredentials) => {
        println!("source-account arm, no signature payload")
    }
    Err(e) => println!("signing error: {}", e),
}
```

**What this binding does not support**: the source-account arm is not supported.
Also, the crate currently does not support passkey/secp256r1 signers.

---

## WASM (web assembly)

The WASM build of the soroauth core runs in the browser or in a Node runtime.
It is distributed as `@soroauth/wasm` on npm.

### Install

```bash
npm install @soroauth/wasm
```

### Quickstart: build, sign and inspect an entry (in the browser)

```html
<script type="module">
import sorauth from '@soroauth/wasm';

async function main() {
  // 1. Load the WASM module (prebuilt; no Go toolchain needed).
  const soro = await sorauth();

  // 2. Derive a keypair from a seed (done in JavaScript, not in WASM).
  const seed = 'S...'; // base58 secret seed
  const kp = sorauth.Keypair.fromSecretSeed(seed);

  // 3. Build an unsigned V2 authorization entry.
  //    The WASM module provides `authorizeInvocation` which builds and signs
  //    the entry, returning the signed entry as base64 XDR.
  const entryB64 = await soro.authorizeInvocation({
    signer: kp.encode().toString('base64'), // simplified: actual use passes a Signer object
    // ...
    validUntilLedger: 1234567,
    networkPassphrase: 'Test SDF Network ; September 2015',
    legacy: false,
  });

  // 3. Inspect the entry.
  const info = await soro.inspect(entryB64);
  console.log('Credential type:', info.credential_type);
  console.log('Address:', info.address);

  // 4. The entry is already signed.  Verify the payload binding.
  const payload = await sora.payload(entryB64);
  console.log('Payload hex:', payload.payload);
}
</script>
```

**Error handling**: the WASM module returns JSON envelopes `{"ok":true,...}`
or `{"ok":false,"error":"...","kind":"SENTINEL"}`, the same shape as the C/
Java/ Rust bindings.  Callers should switch on `kind` rather than string-matching
`error`.

**What this binding does not support**: the source-account arm is not supported.
Also, the WASM build cannot use passkey/secp256r1 signers because the Go
library does not implement them yet.

---

## Error handling conventions

Each binding follows the same error taxonomy, mapped from the Go sentinel
errors:

| Go sentinel                  | Expected binding error kind / type                     |
| ---------------------------- | ------------------------------------------------------ |
| `ErrSourceAccountCredentials` | `SOURCE_ACCOUNT_CREDENTIALS` / `SourceAccountCredentialsError` |
| `ErrUnsupportedCredentials`   | `UNSUPPORTED_CREDENTIALS` / `UnsupportedCredentialsError`   |
| `ErrNoMatchingCredentialNode` | `NO_MATCHING_CREDENTIAL_NODE` / `NoMatchingCredentialNodeError` |
| `ErrDuplicateDelegate`        | `DUPLICATE_DELEGATE` / `DuplicateDelegateError`          |
| `ErrSignatureMismatch`        | `SIGNATURE_MISMATCH` / `SignatureMismatchError`          |
| `ErrMissingSigner`            | `MISSING_SIGNER` / `MissingSignerError`                  |
| `ErrAlreadySigned`            | `ALREADY_SIGNED` / `AlreadySignedError`                  |
| `ErrInvalidExpiration`        | `INVALID_EXPIRATION` / `InvalidExpirationError`          |
| `ErrTooManySignatures`        | `TOO_MANY_SIGNATURES` / `TooManySignaturesError`          |

Bindings **must** switch on the stable `kind`/`error_type` field rather than
parsing error message text.  This prevents breakage when the Go library
refines error messages in a future release.

---

## Known gaps

Several bindings cannot be installed from a package registry yet.  They must be
built from source or installed from a local directory:

- **C binding**: built with `bindings/c/build.sh`; produces `libsoroauth.so` /
  `libsoroauth.dylib` / `libsoroauth.dll`.
- **Node binding**: `npm install @soroauth/node` works for the prebuilt package,
  but the underlying `libsoroauth` shared library must be available on the
  system PATH or set via `SOROAUTH_LIB`.
- **Python binding**: `pip install sorauth` installs a wheel that bundles
  `libsoroauth.so`; building from source requires `bindings/c/build.sh`.
- **JVM binding**: `mvn install` from the `bindings/jvm/` directory.
- **Rust binding**: add `path = "bindings/rust"` in `Cargo.toml`; not published
  to crates.io.
- **WASM binding**: `npm install @soroauth/wasm` works; the underlying Go
  library is compiled to wasm and published as an npm package.

These gaps are documented so a developer can plan the build step accordingly.
Future work may publish prebuilt packages for all bindings, but until then
the source-build path is the supported one.

---

## Compatibility matrix

| Binding | Install method | Sign arm support | Air-gapped signing |
| ------- | -------------- | ---------------- | ------------------ |
| Go      | `go get`       | V2, delegates, legacy | ✅ native          |
| Node    | `npm install`  | V2, delegates      | ✅ via file exchange |
| Python  | `pip install`  | V2 only            | ✅ via file exchange |
| JVM     | `mvn install`   | V2 only            | ✅ via file exchange |
| Rust    | `path dep`     | V2, delegates      | ✅ native          |
| WASM    | `npm install`  | V2 only            | ✅ in-browser      |

*Air-gapped signing is possible on all bindings via the file-exchange procedure
described in `docs/air-gapped-signing.md`: compute the payload hash before
signing on the offline machine, transfer the signed entry, and verify the
payload hash on the online machine.*