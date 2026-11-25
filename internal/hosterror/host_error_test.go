package hosterror

import (
	"errors"
	"testing"
)

func TestMapHostError(t *testing.T) {
	tests := []struct {
		hostError     string
		wantMapped    bool // true if we expect a mapped error, false if unmapped
	}{
		{
			hostError: "signature has expired",
			wantMapped: true,
		},
		{
			hostError: "nonce already exists for address",
			wantMapped: true,
		},
		{
			hostError: "signature weight is lower than threshold",
			wantMapped: true,
		},
		{
			hostError: "UnknownDelegate",
			wantMapped: true,
		},
		{
			hostError: "some random unknown error",
			wantMapped: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.hostError, func(t *testing.T) {
			got := MapHostError(tt.hostError)
			gotName := got.Error()

			if tt.wantMapped {
				// Should be a mapped error (not the unmapped one)
				var e *ErrUnmappedHostError
				if errors.As(got, &e) {
					t.Errorf("MapHostError(%q) returned unmapped error, want mapped error", tt.hostError)
				} else if gotName == "" {
					t.Errorf("MapHostError(%q) = empty error, want mapped error with text", tt.hostError)
				}
			} else {
				// Should be the unmapped error
				var e *ErrUnmappedHostError
				if !errors.As(got, &e) {
					t.Errorf("MapHostError(%q) = %s, want unmapped error (errors.As failed)", tt.hostError, gotName)
				} else if e.RawError != "some random unknown error" {
					t.Errorf("MapHostError(%q) = %s, want raw error 'some random unknown error', got '%s'", tt.hostError, gotName, e.RawError)
				}
			}
		})
	}
}
