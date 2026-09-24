// Package opentelemetry demonstrates how to wire an
// OpenTelemetry-style hook for soroauth signing operations.
//
// The hook implementation uses only the standard library
// and the soroauth.Hook interface. Callers with a real
// OpenTelemetry SDK can replace the stub implementations
// with their OTel imports.
//
// Example usage:
//
//	hook := opentelemetry.NewHook("soroauth-authorize")
//	entry, err := soroauth.AuthorizeEntry(ctx, entry, signer, ledger, passphrase, soroauth.WithHook(hook))
package opentelemetry

import (
	"context"
	"fmt"
	"time"

	"github.com/soroauth/soroauth-go"
)

// Hook is a demonstration hook that records lifecycle
// events. It satisfies the soroauth.Hook interface and
// never receives secret material — only structural metadata.
//
// To use with a real OpenTelemetry SDK, replace the
// Event implementation with OTel span creation.
type Hook struct {
	name   string
	events []Event
}

// Event records one lifecycle observation.
type Event struct {
	Phase            string
	CredentialType   string
	TargetAddress    string
	ValidUntilLedger uint32
	Duration         time.Duration
}

// NewHook creates a new hook with the given instrument name.
func NewHook(name string) *Hook {
	return &Hook{name: name}
}

// Event implements soroauth.Hook, recording each lifecycle
// phase for later inspection.
func (h *Hook) Event(ctx context.Context, e soroauth.HookEvent) error {
	ev := Event{
		Phase:            string(e.Phase),
		CredentialType:   e.CredentialType,
		TargetAddress:    e.TargetAddress,
		ValidUntilLedger: e.ValidUntilLedger,
		Duration:         e.Duration,
	}
	h.events = append(h.events, ev)
	return nil
}

// Events returns the recorded events.
func (h *Hook) Events() []Event {
	return h.events
}

// Summary returns a human-readable summary of all recorded events.
func (h *Hook) Summary() string {
	return fmt.Sprintf("hook %s: %d events recorded", h.name, len(h.events))
}

// MeasureSign measures the timing of a signing operation
// and returns the elapsed time. This is provided as a
// convenience for callers who want timing data without
// the hook system.
func MeasureSign(fn func() error) time.Duration {
	start := time.Now()
	_ = fn()
	return time.Since(start)
}
