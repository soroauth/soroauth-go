package soroauth

import (
	"fmt"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// CredentialArm identifies a Soroban credentials arm and encapsulates its
// behavior. This centralizes arm-specific logic that was previously scattered
// across preimage.go, authorize.go, delegates.go, inspect.go, upgrade.go, and
// batch.go. Adding a new arm should only require adding a new entry to the
// arms map and implementing the ArmBehavior interface.
type CredentialArm string

const (
	ArmSourceAccount        CredentialArm = "source_account"
	ArmAddress              CredentialArm = "address"
	ArmAddressV2            CredentialArm = "address_v2"
	ArmAddressWithDelegates CredentialArm = "address_with_delegates"
)

// ArmBehavior defines the operations that vary by credential arm.
// All methods are pure functions of the entry and parameters.
type ArmBehavior interface {
	// PreimageVariant returns the EnvelopeType for this arm's preimage.
	PreimageVariant() xdr.EnvelopeType

	// IsAddressBound returns true if the signer address is included in the payload.
	IsAddressBound() bool

	// CredentialTypeName returns the stable string name for this arm.
	CredentialTypeName() string

	// GetAddress returns the top-level address for this arm, or empty string for source account.
	GetAddress(creds xdr.SorobanCredentials) (string, error)

	// GetNonce returns the nonce for this arm, or 0 for source account.
	GetNonce(creds xdr.SorobanCredentials) int64

	// GetExpiration returns the signature expiration ledger for this arm, or 0 for source account.
	GetExpiration(creds xdr.SorobanCredentials) uint32

	// GetSignature returns the signature for this arm.
	GetSignature(creds xdr.SorobanCredentials) xdr.ScVal

	// SetSignature sets the signature for this arm (mutates a copy).
	SetSignature(creds *xdr.SorobanCredentials, sig xdr.ScVal)

	// SetExpiration sets the expiration for this arm (mutates a copy).
	SetExpiration(creds *xdr.SorobanCredentials, exp uint32)

	// HasDelegates returns true if this arm supports delegates.
	HasDelegates() bool

	// GetDelegates returns the delegates for this arm, or nil.
	GetDelegates(creds xdr.SorobanCredentials) []xdr.SorobanDelegateSignature

	// SetDelegates sets the delegates for this arm (mutates a copy).
	SetDelegates(creds *xdr.SorobanCredentials, delegates []xdr.SorobanDelegateSignature)

	// CanUpgradeToV2 returns true if this arm can be upgraded to V2.
	CanUpgradeToV2() bool

	// UpgradeToV2 returns the V2 credentials for this arm, or error.
	UpgradeToV2(creds xdr.SorobanCredentials) (xdr.SorobanCredentials, error)

	// ValidateForSigning checks if this arm can be signed with the given target address.
	ValidateForSigning(creds xdr.SorobanCredentials, targetAddress string) error
}

// armBehaviors holds the concrete implementations for each arm.
var armBehaviors = map[CredentialArm]ArmBehavior{
	ArmSourceAccount:        &sourceAccountArm{},
	ArmAddress:              &legacyAddressArm{},
	ArmAddressV2:            &addressV2Arm{},
	ArmAddressWithDelegates: &delegatesArm{},
}

// GetArmBehavior returns the behavior for the given credentials type, or error if unknown.
func GetArmBehavior(creds xdr.SorobanCredentials) (ArmBehavior, error) {
	arm := credentialTypeToArm(creds.Type)
	if arm == "" {
		return nil, ErrUnsupportedCredentials
	}
	behavior, ok := armBehaviors[arm]
	if !ok {
		return nil, ErrUnsupportedCredentials
	}
	return behavior, nil
}

// GetArmBehaviorByName returns the behavior for the given arm name, or error if unknown.
func GetArmBehaviorByName(armName string) (ArmBehavior, error) {
	arm := CredentialArm(armName)
	behavior, ok := armBehaviors[arm]
	if !ok {
		return nil, ErrUnsupportedCredentials
	}
	return behavior, nil
}

// credentialTypeToArm maps XDR credentials type to our internal arm.
func credentialTypeToArm(t xdr.SorobanCredentialsType) CredentialArm {
	switch t {
	case xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount:
		return ArmSourceAccount
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddress:
		return ArmAddress
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2:
		return ArmAddressV2
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates:
		return ArmAddressWithDelegates
	default:
		return ""
	}
}

// sourceAccountArm implements ArmBehavior for SOURCE_ACCOUNT.
type sourceAccountArm struct{}

func (a *sourceAccountArm) PreimageVariant() xdr.EnvelopeType {
	// Source account has no preimage - the tx envelope covers it
	return xdr.EnvelopeType(99) // Invalid, should not be called
}

func (a *sourceAccountArm) IsAddressBound() bool {
	return false
}

func (a *sourceAccountArm) CredentialTypeName() string {
	return CredentialTypeSourceAccount
}

func (a *sourceAccountArm) GetAddress(creds xdr.SorobanCredentials) (string, error) {
	return "", nil
}

func (a *sourceAccountArm) GetNonce(creds xdr.SorobanCredentials) int64 {
	return 0
}

func (a *sourceAccountArm) GetExpiration(creds xdr.SorobanCredentials) uint32 {
	return 0
}

func (a *sourceAccountArm) GetSignature(creds xdr.SorobanCredentials) xdr.ScVal {
	return xdr.ScVal{Type: xdr.ScValTypeScvVoid}
}

func (a *sourceAccountArm) SetSignature(creds *xdr.SorobanCredentials, sig xdr.ScVal) {
	// No-op for source account
}

func (a *sourceAccountArm) SetExpiration(creds *xdr.SorobanCredentials, exp uint32) {
	// No-op for source account
}

func (a *sourceAccountArm) HasDelegates() bool {
	return false
}

func (a *sourceAccountArm) GetDelegates(creds xdr.SorobanCredentials) []xdr.SorobanDelegateSignature {
	return nil
}

func (a *sourceAccountArm) SetDelegates(creds *xdr.SorobanCredentials, delegates []xdr.SorobanDelegateSignature) {
	// No-op
}

func (a *sourceAccountArm) CanUpgradeToV2() bool {
	return false
}

func (a *sourceAccountArm) UpgradeToV2(creds xdr.SorobanCredentials) (xdr.SorobanCredentials, error) {
	return xdr.SorobanCredentials{}, ErrUnsupportedCredentials
}

func (a *sourceAccountArm) ValidateForSigning(creds xdr.SorobanCredentials, targetAddress string) error {
	// Source account entries don't get signed
	return ErrSourceAccountCredentials
}

// legacyAddressArm implements ArmBehavior for ADDRESS (legacy V1).
type legacyAddressArm struct{}

func (a *legacyAddressArm) PreimageVariant() xdr.EnvelopeType {
	return xdr.EnvelopeTypeEnvelopeTypeSorobanAuthorization
}

func (a *legacyAddressArm) IsAddressBound() bool {
	return false
}

func (a *legacyAddressArm) CredentialTypeName() string {
	return CredentialTypeAddress
}

func (a *legacyAddressArm) GetAddress(creds xdr.SorobanCredentials) (string, error) {
	if creds.Address == nil {
		return "", fmt.Errorf("address credentials arm is empty")
	}
	return FormatAddress(creds.Address.Address)
}

func (a *legacyAddressArm) GetNonce(creds xdr.SorobanCredentials) int64 {
	if creds.Address == nil {
		return 0
	}
	return int64(creds.Address.Nonce)
}

func (a *legacyAddressArm) GetExpiration(creds xdr.SorobanCredentials) uint32 {
	if creds.Address == nil {
		return 0
	}
	return uint32(creds.Address.SignatureExpirationLedger)
}

func (a *legacyAddressArm) GetSignature(creds xdr.SorobanCredentials) xdr.ScVal {
	if creds.Address == nil {
		return xdr.ScVal{Type: xdr.ScValTypeScvVoid}
	}
	return creds.Address.Signature
}

func (a *legacyAddressArm) SetSignature(creds *xdr.SorobanCredentials, sig xdr.ScVal) {
	if creds.Address != nil {
		creds.Address.Signature = sig
	}
}

func (a *legacyAddressArm) SetExpiration(creds *xdr.SorobanCredentials, exp uint32) {
	if creds.Address != nil {
		creds.Address.SignatureExpirationLedger = xdr.Uint32(exp)
	}
}

func (a *legacyAddressArm) HasDelegates() bool {
	return false
}

func (a *legacyAddressArm) GetDelegates(creds xdr.SorobanCredentials) []xdr.SorobanDelegateSignature {
	return nil
}

func (a *legacyAddressArm) SetDelegates(creds *xdr.SorobanCredentials, delegates []xdr.SorobanDelegateSignature) {
	// No-op
}

func (a *legacyAddressArm) CanUpgradeToV2() bool {
	return true
}

func (a *legacyAddressArm) UpgradeToV2(creds xdr.SorobanCredentials) (xdr.SorobanCredentials, error) {
	if creds.Address == nil {
		return xdr.SorobanCredentials{}, fmt.Errorf("legacy credentials arm is empty")
	}
	if isSigned(creds.Address.Signature) {
		return xdr.SorobanCredentials{}, ErrAlreadySigned
	}
	return xdr.SorobanCredentials{
		Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
		AddressV2: &xdr.SorobanAddressCredentials{
			Address:                   creds.Address.Address,
			Nonce:                     creds.Address.Nonce,
			SignatureExpirationLedger: creds.Address.SignatureExpirationLedger,
			Signature:                 xdr.ScVal{Type: xdr.ScValTypeScvVoid},
		},
	}, nil
}

func (a *legacyAddressArm) ValidateForSigning(creds xdr.SorobanCredentials, targetAddress string) error {
	if creds.Address == nil {
		return fmt.Errorf("legacy address credentials arm is empty")
	}
	addr, err := FormatAddress(creds.Address.Address)
	if err != nil {
		return err
	}
	if addr != targetAddress {
		return ErrNoMatchingCredentialNode
	}
	return nil
}

// addressV2Arm implements ArmBehavior for ADDRESS_V2.
type addressV2Arm struct{}

func (a *addressV2Arm) PreimageVariant() xdr.EnvelopeType {
	return xdr.EnvelopeTypeEnvelopeTypeSorobanAuthorizationWithAddress
}

func (a *addressV2Arm) IsAddressBound() bool {
	return true
}

func (a *addressV2Arm) CredentialTypeName() string {
	return CredentialTypeAddressV2
}

func (a *addressV2Arm) GetAddress(creds xdr.SorobanCredentials) (string, error) {
	if creds.AddressV2 == nil {
		return "", fmt.Errorf("address_v2 credentials arm is empty")
	}
	return FormatAddress(creds.AddressV2.Address)
}

func (a *addressV2Arm) GetNonce(creds xdr.SorobanCredentials) int64 {
	if creds.AddressV2 == nil {
		return 0
	}
	return int64(creds.AddressV2.Nonce)
}

func (a *addressV2Arm) GetExpiration(creds xdr.SorobanCredentials) uint32 {
	if creds.AddressV2 == nil {
		return 0
	}
	return uint32(creds.AddressV2.SignatureExpirationLedger)
}

func (a *addressV2Arm) GetSignature(creds xdr.SorobanCredentials) xdr.ScVal {
	if creds.AddressV2 == nil {
		return xdr.ScVal{Type: xdr.ScValTypeScvVoid}
	}
	return creds.AddressV2.Signature
}

func (a *addressV2Arm) SetSignature(creds *xdr.SorobanCredentials, sig xdr.ScVal) {
	if creds.AddressV2 != nil {
		creds.AddressV2.Signature = sig
	}
}

func (a *addressV2Arm) SetExpiration(creds *xdr.SorobanCredentials, exp uint32) {
	if creds.AddressV2 != nil {
		creds.AddressV2.SignatureExpirationLedger = xdr.Uint32(exp)
	}
}

func (a *addressV2Arm) HasDelegates() bool {
	return false
}

func (a *addressV2Arm) GetDelegates(creds xdr.SorobanCredentials) []xdr.SorobanDelegateSignature {
	return nil
}

func (a *addressV2Arm) SetDelegates(creds *xdr.SorobanCredentials, delegates []xdr.SorobanDelegateSignature) {
	// No-op
}

func (a *addressV2Arm) CanUpgradeToV2() bool {
	return false
}

func (a *addressV2Arm) UpgradeToV2(creds xdr.SorobanCredentials) (xdr.SorobanCredentials, error) {
	// Already V2, return copy
	if creds.AddressV2 == nil {
		return xdr.SorobanCredentials{}, fmt.Errorf("address_v2 credentials arm is empty")
	}
	return creds, nil
}

func (a *addressV2Arm) ValidateForSigning(creds xdr.SorobanCredentials, targetAddress string) error {
	if creds.AddressV2 == nil {
		return fmt.Errorf("address_v2 credentials arm is empty")
	}
	addr, err := FormatAddress(creds.AddressV2.Address)
	if err != nil {
		return err
	}
	if addr != targetAddress {
		return ErrNoMatchingCredentialNode
	}
	return nil
}

// delegatesArm implements ArmBehavior for ADDRESS_WITH_DELEGATES.
type delegatesArm struct{}

func (a *delegatesArm) PreimageVariant() xdr.EnvelopeType {
	return xdr.EnvelopeTypeEnvelopeTypeSorobanAuthorizationWithAddress
}

func (a *delegatesArm) IsAddressBound() bool {
	return true
}

func (a *delegatesArm) CredentialTypeName() string {
	return CredentialTypeAddressWithDelegates
}

func (a *delegatesArm) GetAddress(creds xdr.SorobanCredentials) (string, error) {
	if creds.AddressWithDelegates == nil {
		return "", fmt.Errorf("address_with_delegates credentials arm is empty")
	}
	return FormatAddress(creds.AddressWithDelegates.AddressCredentials.Address)
}

func (a *delegatesArm) GetNonce(creds xdr.SorobanCredentials) int64 {
	if creds.AddressWithDelegates == nil {
		return 0
	}
	return int64(creds.AddressWithDelegates.AddressCredentials.Nonce)
}

func (a *delegatesArm) GetExpiration(creds xdr.SorobanCredentials) uint32 {
	if creds.AddressWithDelegates == nil {
		return 0
	}
	return uint32(creds.AddressWithDelegates.AddressCredentials.SignatureExpirationLedger)
}

func (a *delegatesArm) GetSignature(creds xdr.SorobanCredentials) xdr.ScVal {
	if creds.AddressWithDelegates == nil {
		return xdr.ScVal{Type: xdr.ScValTypeScvVoid}
	}
	return creds.AddressWithDelegates.AddressCredentials.Signature
}

func (a *delegatesArm) SetSignature(creds *xdr.SorobanCredentials, sig xdr.ScVal) {
	if creds.AddressWithDelegates != nil {
		creds.AddressWithDelegates.AddressCredentials.Signature = sig
	}
}

func (a *delegatesArm) SetExpiration(creds *xdr.SorobanCredentials, exp uint32) {
	if creds.AddressWithDelegates != nil {
		creds.AddressWithDelegates.AddressCredentials.SignatureExpirationLedger = xdr.Uint32(exp)
	}
}

func (a *delegatesArm) HasDelegates() bool {
	return true
}

func (a *delegatesArm) GetDelegates(creds xdr.SorobanCredentials) []xdr.SorobanDelegateSignature {
	if creds.AddressWithDelegates == nil {
		return nil
	}
	return creds.AddressWithDelegates.Delegates
}

func (a *delegatesArm) SetDelegates(creds *xdr.SorobanCredentials, delegates []xdr.SorobanDelegateSignature) {
	if creds.AddressWithDelegates != nil {
		creds.AddressWithDelegates.Delegates = delegates
	}
}

func (a *delegatesArm) CanUpgradeToV2() bool {
	return false
}

func (a *delegatesArm) UpgradeToV2(creds xdr.SorobanCredentials) (xdr.SorobanCredentials, error) {
	return xdr.SorobanCredentials{}, ErrUnsupportedCredentials
}

func (a *delegatesArm) ValidateForSigning(creds xdr.SorobanCredentials, targetAddress string) error {
	if creds.AddressWithDelegates == nil {
		return fmt.Errorf("address_with_delegates credentials arm is empty")
	}
	addr, err := FormatAddress(creds.AddressWithDelegates.AddressCredentials.Address)
	if err != nil {
		return err
	}
	if addr != targetAddress {
		return ErrNoMatchingCredentialNode
	}
	return nil
}
