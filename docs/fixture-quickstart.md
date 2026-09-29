# Fixture Contract Quickstart

This guide walks through building and deploying the e2e fixture contracts from a
clean checkout. The fixtures are small Soroban contracts that exercise specific
authentication paths; they are **test fixtures only**, not audited or
feature-complete smart accounts.

## Prerequisites

From a clean checkout you need:

- **Rust 1.93.0** (pinned, see [Toolchain](#toolchain) below)
- **`wasm32v1-none` target** — `rustup target add wasm32v1-none`
- **`stellar-cli` 28.0.0** — the Soroban CLI for building and deploying

No Stellar accounts or network access are required to **build** the contracts.
Deployment requires a funded testnet account and an RPC endpoint.

## Toolchain

The exact pinned toolchain is declared in
[`e2e/contracts/rust-toolchain.toml`](e2e/contracts/rust-toolchain.toml):

```toml
# Pinned to satisfy the higher of the two rust-version floors this build needs:
#   soroban-sdk 27.0.6 declares rust-version = "1.91.0"
#   stellar-cli 28.0.0 declares rust-version = "1.93.0"
# 1.91.0 would build the contract crate alone but not the CLI that builds it,
# so the pin is 1.93.0.
[toolchain]
channel = "1.93.0"
targets = ["wasm32v1-none"]
```

**Why this pin:** `soroban-sdk` 27.0.6 (used by the fixture contracts) declares a
minimum Rust version of 1.91.0. However, `stellar-cli` 28.0.0 (the tool that
compiles contracts to Wasm) declares a minimum Rust version of 1.93.0. Using
1.91.0 would allow the contract crates to compile in isolation, but the CLI
that performs the build would fail. The pin at 1.93.0 satisfies both.

If you use `rustup`, it will automatically fetch and use 1.93.0 when you `cd`
into `e2e/contracts/`.

## Build

From the repository root:

```sh
cd e2e/contracts
stellar contract build
```

This compiles all six workspace members (`modular-account`, `passkey-wallet`,
`policy-account`, `session-keys`, `threshold-account`, `social-recovery`) and
places the optimized Wasm binaries in `target/wasm32v1-none/release/`.

The build uses the release profile from the workspace `Cargo.toml`:
size-optimized (`opt-level = "z"`), stripped, panic-on-abort, with LTO — the
standard Soroban deployment profile.

### Verify the build

```sh
ls -lh target/wasm32v1-none/release/*.wasm
```

You should see one `.wasm` file per fixture (e.g.,
`modular_account.wasm`, `session_keys.wasm`, etc.).

### Run contract unit tests

Each fixture has Rust unit tests covering its constructor, `__check_auth`
logic, and error paths:

```sh
cargo test --workspace
```

Expected passing tests include:
- `modular-account`: constructor storage, `NoDelegates`, `UnknownDelegate`
- `session-keys`: window registration, in-window acceptance, expiry rejection
- `threshold-account`: M-of-N threshold, exactly M signers, M-1 rejection
- `policy-account`: within-limit and over-limit spending
- `passkey-wallet`: P-256 key registration, valid signature, corrupted signature

## Deploy

Deployment targets **Stellar testnet** (Protocol 28+, which includes CAP-71).
You need:

1. A funded testnet account (source account for deployment transactions).
2. An RPC endpoint — the default is `https://soroban-testnet.stellar.org`.
3. `stellar-cli` 28.0.0 authenticated with your source account's secret key.

### One-time setup

```sh
# Create or import a testnet identity for stellar-cli
stellar keys generate --global testnet-deployer --network testnet
# Fund it via friendbot (https://laboratory.stellar.org/#account-creator)
stellar keys address testnet-deployer
```

### Deploy a single fixture

```sh
cd e2e/contracts
stellar contract deploy \
  --wasm target/wasm32v1-none/release/modular_account.wasm \
  --source testnet-deployer \
  --network testnet \
  -- \
  --signers '["<G-ACCOUNT-1>", "<G-ACCOUNT-2>"]'
```

Replace `<G-ACCOUNT-1>` and `<G-ACCOUNT-2>` with the G… addresses you want as
delegated signers for the modular account. The constructor arguments vary by
fixture:

| Fixture           | Constructor arguments (JSON array)                                                                           |
| ----------------- | ------------------------------------------------------------------------------------------------------------ |
| `modular-account` | `--signers '["G...", "G..."]'`                                                                               |
| `session-keys`    | *(no constructor args; session keys registered via contract calls)*                                          |
| `threshold-account`| `--threshold 2 --signers '["G...", "G...", "G..."]'`                                                        |
| `policy-account`  | `--limit 10000000 --period 100 --signer "G..."`                                                              |
| `passkey-wallet`  | `--credential_key "<P256_PUBLIC_KEY_BASE64>"`                                                                |
| `social-recovery` | `--guardians '["G...", "G..."] --signer "G..." --delay 10`                                                  |

**Note:** The e2e test suite generates accounts and deploys fixtures
programmatically at runtime (see `e2e/deploy_test.go`). The CLI commands above
are for manual debugging only; the test suite does not require manual deployment.

### Verify deployment

After deployment, `stellar-cli` prints the contract ID (a `C…` address). You can
inspect the deployed contract:

```sh
stellar contract invoke \
  --id <CONTRACT_ID> \
  --source testnet-deployer \
  --network testnet \
  -- \
  signers
```

For `modular-account`, this returns the list of registered signers.

## Running the e2e tests

Once fixtures are built (the `stellar contract build` step above), run the Go
e2e suite:

```sh
cd ../..  # back to repository root
go test -tags e2e -v ./e2e/...
```

This runs all live scenarios against testnet, using the just-built Wasm
binaries. The suite generates its own accounts, deploys contracts, and funds
them via friendbot — no manual deployment is needed for the test run.

## Troubleshooting

| Problem                                                  | Resolution                                                                                          |
| -------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `error: toolchain '1.93.0' not installed`                | Run `rustup install 1.93.0 && rustup target add wasm32v1-none --toolchain 1.93.0`                 |
| `stellar: command not found`                             | Install `stellar-cli` 28.0.0: `cargo install --locked stellar-cli@28.0.0`                          |
| `failed to build: crate requires rustc 1.93`             | You are not using the pinned toolchain; `cd e2e/contracts` and ensure `rustup show` reports 1.93.0 |
| `wasm32v1-none target not found`                         | `rustup target add wasm32v1-none --toolchain 1.93.0`                                               |
| Build succeeds but e2e tests fail with RPC errors        | Check `SOROAUTH_RPC_URL` (default `https://soroban-testnet.stellar.org`) and testnet status        |
| Contract deployment fails with "insufficient balance"    | Fund the source account via friendbot before deploying                                             |

## Related documentation

- [E2E test scenarios](e2e/README.md) — what each live scenario proves
- [Fixture inventory](FIXTURES.md) — detailed table of all fixtures, their paths, and evidence
- [CONTRIBUTING.md](../CONTRIBUTING.md#running-the-e2e-tests) — the one-liner for the full e2e run