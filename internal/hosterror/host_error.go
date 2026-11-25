package hosterror

import (
	"errors"
	"fmt"
	"strings"
)

// hostErrorMapping maps host authorization failure messages to the library's
// typed errors.  Each entry documents the host source where the message is
// produced, so operators can identify the root cause of an on-chain rejection.
// The host error message is matched as a substring of the host's raw error;
// if no entry matches, the function returns an error wrapping the raw host error text.
type hostErrorMapping struct {
	MessageFragment string
	LibraryError    error
	HostSource      string
}

// HostErrorMap is the complete, documented mapping from host authorization
// failure messages to library sentinel errors.
var HostErrorMap = []hostErrorMapping{
	{
		MessageFragment: "signature has expired",
		LibraryError:    errors.New("soroauth: invalid signature expiration ledger"),
		HostSource:      "rs-soroban-env soroban-env-host/src/auth.rs, verify_and_consume_nonce: rejects when current_ledger > signatureExpirationLedger",
	},
	{
		MessageFragment: "nonce already exists for address",
		LibraryError:    errors.New("soroauth: nonce already reserved for this address"),
		HostSource:      "rs-soroban-env soroban-env-host/src/auth.rs, consume_nonce: rejects when a nonce is reused for the same address",
	},
	{
		MessageFragment: "signature weight is lower than threshold",
		LibraryError:    errors.New("soroauth: too many signatures for a classic account"),
		HostSource:      "rs-soroban-env builtin_contracts/account_contract.rs, check_account_authentication: weight < medium threshold",
	},
	{
		MessageFragment: "UnknownDelegate",
		LibraryError:    errors.New("soroauth: no credential node matches the target address"),
		HostSource:      "e2e/contracts/modular-account/src/lib.rs, AccountError::UnknownDelegate: delegate not in stored signers set",
	},
}

// ErrUnmappedHostError is returned when a host error message does not match
// any entry in HostErrorMap.  The error message includes the raw host error
// so the operator can see what was unrecognized.
type ErrUnmappedHostError struct {
	RawError string
}

func (e *ErrUnmappedHostError) Error() string {
	return fmt.Sprintf("soroauth: unmapped host error (raw: %s)", e.RawError)
}

func (e *ErrUnmappedHostError) Unwrap() error {
	return errors.New("soroauth: unmapped host error")
}

// MapHostError returns the library error corresponding to the given host error
// message, if one exists.  If no mapping matches, it returns
// *ErrUnmappedHostError wrapping the raw host error text.
func MapHostError(hostError string) error {
	for _, m := range HostErrorMap {
		if strings.Contains(hostError, m.MessageFragment) {
			return m.LibraryError
		}
	}
	return &ErrUnmappedHostError{RawError: hostError}
}

// IsUnmapped reports whether err is an unmapped host error.
func IsUnmapped(err error) bool {
	return errors.Is(err, &ErrUnmappedHostError{})
}
