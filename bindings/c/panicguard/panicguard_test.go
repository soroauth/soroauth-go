package panicguard_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/soroauth/soroauth-go/bindings/c/panicguard"
)

// TestInducedPanicProducesEnvelopeMessage deliberately induces a panic behind
// the recover/Message boundary, asserts the process survives and that the
// message the ABI would return follows the fixed shape every binding parses.
func TestInducedPanicProducesEnvelopeMessage(t *testing.T) {
	msg, recovered := runWithRecover(func() {
		var p *int
		_ = *p // induces an actual runtime panic
	})
	if !recovered {
		t.Fatal("deferred recover did not fire for a nil-pointer deref")
	}
	if !strings.HasPrefix(msg, panicguard.MessagePrefix) {
		t.Errorf("message = %q, want prefix %q", msg, panicguard.MessagePrefix)
	}
	if strings.Contains(msg, "\n") || strings.Contains(msg, "\r") {
		t.Errorf("message must not carry newlines (stack-leak guard), got %q", msg)
	}
	if strings.Contains(msg, "goroutine ") || strings.Contains(msg, ".go:") {
		t.Errorf("message must not look like a Go stack trace, got %q", msg)
	}
}

// TestMessageSanitisesNewlines proves a multi-line panic value becomes one
// clean line in the envelope. A stack-looking panic value must not produce a
// JSON string that leaks a stack across the ABI boundary.
func TestMessageSanitisesNewlines(t *testing.T) {
	msg := panicguard.Message("line one\nline two\r\nline three\rline four")
	if strings.Contains(msg, "\n") || strings.Contains(msg, "\r") {
		t.Errorf("Message did not strip newlines: %q", msg)
	}
	for _, part := range []string{"line one", "line two", "line three", "line four"} {
		if !strings.Contains(msg, part) {
			t.Errorf("Message dropped %q: %q", part, msg)
		}
	}
}

// TestMessageFromErrorValue proves the same bridge works when the panic value
// is an error, which is the shape the library's own panics would take.
func TestMessageFromErrorValue(t *testing.T) {
	msg := panicguard.Message(errors.New("something went wrong"))
	if !strings.Contains(msg, "something went wrong") {
		t.Errorf("Message did not carry the error string: %q", msg)
	}
	if !strings.HasPrefix(msg, panicguard.MessagePrefix) {
		t.Errorf("Message missing prefix: %q", msg)
	}
}

// TestKindIsStable pins the sentinel the error envelope carries. Bindings
// switch on this string; changing it is an ABI break.
func TestKindIsStable(t *testing.T) {
	if panicguard.Kind != "PANIC" {
		t.Errorf("Kind = %q, want PANIC", panicguard.Kind)
	}
}

// runWithRecover mirrors the ABI's deferred guard: the body may panic, the
// deferred recover converts it into the envelope message, and the caller sees
// (message, true) instead of a crashed process. It is the test-side
// equivalent of what catchPanic does in soroauth.go.
func runWithRecover(body func()) (msg string, recovered bool) {
	defer func() {
		if r := recover(); r != nil {
			msg = panicguard.Message(r)
			recovered = true
		}
	}()
	body()
	return "", false
}
