package soroauth

// ArmProtocolVersion records the Stellar protocol version each credential
// arm's CAP was introduced in, so a caller pointing this library at an older
// network gets an early, specific answer instead of a confusing on-chain
// failure.
//
// Values are read from each CAP document's own preamble, not estimated:
//
//   - SOROBAN_CREDENTIALS_SOURCE_ACCOUNT and SOROBAN_CREDENTIALS_ADDRESS are
//     both defined by CAP-46-11 ("Soroban Authorization Framework"), whose
//     preamble states "Protocol version: 20"
//     (https://github.com/stellar/stellar-protocol/blob/master/core/cap-0046-11.md).
//   - SOROBAN_CREDENTIALS_ADDRESS_V2 is defined by CAP-71-01 ("Delegated
//     Authorization and Recallable Signing" address-bound V2 credentials
//     preimage), whose preamble states "Protocol version: 27"
//     (https://github.com/stellar/stellar-protocol/blob/master/core/cap-0071-01.md).
//   - SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES is defined by CAP-71-02
//     (the delegated-signer credential type itself), whose preamble also
//     states "Protocol version: 27"
//     (https://github.com/stellar/stellar-protocol/blob/master/core/cap-0071-02.md).
//
// A network on an older protocol than the value here cannot emit or accept
// that arm at all: simulateTransaction on such a network never returns it,
// and the host rejects a transaction that names a credentials type the
// running protocol does not implement. This library does not check a
// caller's live network protocol version — doing so would require an RPC
// call this library does not make (see the non-goals in doc.go) — so this
// matrix exists to make the requirement visible in code and in the README,
// not to enforce it at runtime.
var ArmProtocolVersion = map[string]int{
	CredentialTypeSourceAccount:        20,
	CredentialTypeAddress:              20,
	CredentialTypeAddressV2:            27,
	CredentialTypeAddressWithDelegates: 27,
}
