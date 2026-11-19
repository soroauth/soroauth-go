package soroauth

import (
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"
)

func TestExpirationAfter(t *testing.T) {
	tests := []struct {
		name         string
		latestLedger uint32
		ledgers      uint32
		want         uint32
	}{
		{name: "one ledger ahead", latestLedger: 1000, ledgers: 1, want: 1001},
		{name: "an hour of ledgers", latestLedger: 1234567, ledgers: 720, want: 1235287},
		// The rows of the worked example in the ExpirationAfter doc comment;
		// "one ledger ahead" above and "zero ledgers" in the rejects test are
		// the other two.
		{name: "doc comment worked example", latestLedger: 1000, ledgers: 720, want: 1720},
		{name: "from genesis", latestLedger: 0, ledgers: 100, want: 100},
		{
			name:         "the largest sum that still fits",
			latestLedger: math.MaxUint32 - 1,
			ledgers:      1,
			want:         math.MaxUint32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExpirationAfter(tt.latestLedger, tt.ledgers)
			if err != nil {
				t.Fatalf("ExpirationAfter returned an unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestExpirationAfterRejects(t *testing.T) {
	tests := []struct {
		name         string
		latestLedger uint32
		ledgers      uint32
		wantMsg      string
	}{
		{
			name:         "zero ledgers",
			latestLedger: 1000,
			ledgers:      0,
			wantMsg:      "at least 1",
		},
		{
			name:         "overflow by one",
			latestLedger: math.MaxUint32,
			ledgers:      1,
			wantMsg:      "overflows",
		},
		{
			name:         "overflow by a lot",
			latestLedger: math.MaxUint32 - 10,
			ledgers:      1000,
			wantMsg:      "overflows",
		},
		{
			name:         "both operands at the maximum",
			latestLedger: math.MaxUint32,
			ledgers:      math.MaxUint32,
			wantMsg:      "overflows",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExpirationAfter(tt.latestLedger, tt.ledgers)
			if err == nil {
				t.Fatalf("ExpirationAfter succeeded, returning %d", got)
			}
			if !errors.Is(err, ErrInvalidExpiration) {
				t.Errorf("error %q does not match ErrInvalidExpiration", err)
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("error %q does not mention %q", err, tt.wantMsg)
			}
			if got != 0 {
				t.Errorf("ExpirationAfter returned %d alongside an error, want 0", got)
			}
		})
	}
}

// TestExpirationAfterNeverWraps is the property the overflow check exists for:
// wrapping would turn a long lifetime into an expiration in the past, which the
// host would reject as already expired.
func TestExpirationAfterNeverWraps(t *testing.T) {
	latest := uint32(math.MaxUint32 - 5)
	for ledgers := uint32(1); ledgers <= 20; ledgers++ {
		got, err := ExpirationAfter(latest, ledgers)
		if err != nil {
			continue // refused, which is the correct outcome past the ceiling
		}
		if got < latest {
			t.Fatalf("ExpirationAfter(%d, %d) returned %d, which is in the past",
				latest, ledgers, got)
		}
	}
}

// --- Issue #320: entry expiry and freshness policy helpers ---

// entryWithExpiration builds an entry on the given arm with its
// SignatureExpirationLedger set to exp.
func entryWithExpiration(t *testing.T, armType xdr.SorobanCredentialsType, exp uint32) xdr.SorobanAuthorizationEntry {
	t.Helper()
	entry := entryForArm(t, armType, 42)

	switch armType {
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddress:
		entry.Credentials.Address.SignatureExpirationLedger = xdr.Uint32(exp)
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2:
		entry.Credentials.AddressV2.SignatureExpirationLedger = xdr.Uint32(exp)
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates:
		entry.Credentials.AddressWithDelegates.AddressCredentials.SignatureExpirationLedger = xdr.Uint32(exp)
	}
	return entry
}

func TestCheckExpiration(t *testing.T) {
	arms := []struct {
		name    string
		armType xdr.SorobanCredentialsType
	}{
		{"legacy address", xdr.SorobanCredentialsTypeSorobanCredentialsAddress},
		{"address v2", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2},
		{"delegates", xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates},
	}

	tests := []struct {
		name           string
		exp            uint32
		currentLedger  uint32
		wantValid      bool
		wantRemaining  uint32
		wantExpiration uint32
	}{
		{
			name:           "current ledger well before expiration",
			exp:            1720,
			currentLedger:  1000,
			wantValid:      true,
			wantRemaining:  721,
			wantExpiration: 1720,
		},
		{
			name:           "current ledger one before expiration",
			exp:            1720,
			currentLedger:  1719,
			wantValid:      true,
			wantRemaining:  2,
			wantExpiration: 1720,
		},
		{
			name:           "current ledger equals expiration (inclusive bound)",
			exp:            1720,
			currentLedger:  1720,
			wantValid:      true,
			wantRemaining:  1,
			wantExpiration: 1720,
		},
		{
			name:           "current ledger one past expiration (rejected)",
			exp:            1720,
			currentLedger:  1721,
			wantValid:      false,
			wantRemaining:  0,
			wantExpiration: 1720,
		},
		{
			name:           "current ledger well past expiration",
			exp:            1720,
			currentLedger:  5000,
			wantValid:      false,
			wantRemaining:  0,
			wantExpiration: 1720,
		},
		{
			name:           "expiration at zero, current at zero (valid)",
			exp:            0,
			currentLedger:  0,
			wantValid:      true,
			wantRemaining:  1,
			wantExpiration: 0,
		},
		{
			name:           "expiration at zero, current at one (rejected)",
			exp:            0,
			currentLedger:  1,
			wantValid:      false,
			wantRemaining:  0,
			wantExpiration: 0,
		},
		{
			name:           "expiration at max uint32",
			exp:            math.MaxUint32,
			currentLedger:  math.MaxUint32,
			wantValid:      true,
			wantRemaining:  1,
			wantExpiration: math.MaxUint32,
		},
		{
			name:           "expiration at max uint32 minus one, current at max",
			exp:            math.MaxUint32 - 1,
			currentLedger:  math.MaxUint32,
			wantValid:      false,
			wantRemaining:  0,
			wantExpiration: math.MaxUint32 - 1,
		},
	}

	for _, arm := range arms {
		t.Run(arm.name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					entry := entryWithExpiration(t, arm.armType, tt.exp)
					got, err := CheckExpiration(entry, tt.currentLedger)
					if err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
					if got.Valid != tt.wantValid {
						t.Errorf("Valid = %v, want %v", got.Valid, tt.wantValid)
					}
					if got.RemainingLedgers != tt.wantRemaining {
						t.Errorf("RemainingLedgers = %d, want %d", got.RemainingLedgers, tt.wantRemaining)
					}
					if got.ExpirationLedger != tt.wantExpiration {
						t.Errorf("ExpirationLedger = %d, want %d", got.ExpirationLedger, tt.wantExpiration)
					}
				})
			}
		})
	}
}

func TestCheckExpirationSourceAccountReturnsError(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount, 0)
	_, err := CheckExpiration(entry, 1000)
	if err == nil {
		t.Fatal("CheckExpiration should return an error for source-account entries")
	}
	if !errors.Is(err, ErrSourceAccountCredentials) {
		t.Errorf("error %q does not wrap ErrSourceAccountCredentials", err)
	}
}

func TestIsExpired(t *testing.T) {
	entry := entryWithExpiration(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1720)

	tests := []struct {
		name          string
		currentLedger uint32
		wantExpired   bool
	}{
		{"before expiration", 1000, false},
		{"at expiration (inclusive)", 1720, false},
		{"one past expiration", 1721, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IsExpired(entry, tt.currentLedger)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.wantExpired {
				t.Errorf("IsExpired = %v, want %v", got, tt.wantExpired)
			}
		})
	}
}

func TestIsExpiredSourceAccountReturnsError(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount, 0)
	_, err := IsExpired(entry, 1000)
	if err == nil {
		t.Fatal("IsExpired should return an error for source-account entries")
	}
	if !errors.Is(err, ErrSourceAccountCredentials) {
		t.Errorf("error %q does not wrap ErrSourceAccountCredentials", err)
	}
}

func TestWithinMargin(t *testing.T) {
	entry := entryWithExpiration(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1720)

	tests := []struct {
		name          string
		currentLedger uint32
		margin        uint32
		want          bool
	}{
		{"plenty of margin", 1000, 100, true},
		{"remaining equals margin exactly", 1000, 721, true},
		{"remaining one less than margin", 1000, 722, false},
		{"at expiration, margin 0", 1720, 0, true},
		{"at expiration, margin 1", 1720, 1, true},
		{"at expiration, margin 2", 1720, 2, false},
		{"expired, margin 0", 1721, 0, false},
		{"expired, margin 1", 1721, 1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := WithinMargin(entry, tt.currentLedger, tt.margin)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("WithinMargin = %v, want %v (remaining=%d, margin=%d)",
					got, tt.want, tt.currentLedger, tt.margin)
			}
		})
	}
}

func TestWithinMarginSourceAccountReturnsError(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount, 0)
	_, err := WithinMargin(entry, 1000, 100)
	if err == nil {
		t.Fatal("WithinMargin should return an error for source-account entries")
	}
	if !errors.Is(err, ErrSourceAccountCredentials) {
		t.Errorf("error %q does not wrap ErrSourceAccountCredentials", err)
	}
}

func TestCheckExpirationDelegatesUsesTopLevelExpiration(t *testing.T) {
	entry := entryWithExpiration(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates, 2000)
	got, err := CheckExpiration(entry, 1500)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.Valid {
		t.Error("entry should be valid at ledger 1500 with expiration 2000")
	}
	if got.ExpirationLedger != 2000 {
		t.Errorf("ExpirationLedger = %d, want 2000 (the top-level value)", got.ExpirationLedger)
	}
	if got.RemainingLedgers != 501 {
		t.Errorf("RemainingLedgers = %d, want 501", got.RemainingLedgers)
	}
}
