// Package panicguard is the panic-to-error bridge every //export function in
// bindings/c/soroauth.go uses. It lives in its own package so a regular Go
// test can run with no cgo toolchain and still prove the recovery path.
//
// A Go panic that unwinds out of a cgo-exported function takes the host
// process with it. Every binding (Node, JVM, Python, Rust) loads these
// exported functions, so an unexpected nil or out-of-range in library code
// becomes a hard crash of someone's Node server or JVM rather than an error
// their code can handle. The ABI file defers a recover that calls Message to
// produce the error string the caller receives, and logs the Go stack to
// stderr so an operator still has it for diagnosis.
//
// The envelope kind for a panic is a dedicated sentinel ("PANIC"), so a
// binding can map it to an InternalError (or the equivalent) rather than
// string-matching on the message.
package panicguard

import (
	"fmt"
	"strings"
)

// Kind is the stable envelope kind every binding reads when a panic was
// caught. It is a sentinel of its own, not reused from any library sentinel,
// so a binding sees "this was a bug on the Go side" distinctly from an
// expected failure.
const Kind = "PANIC"

// MessagePrefix is the stable prefix every panic message starts with. Tests
// rely on it to assert the message is well-formed without pinning the rest of
// the string.
const MessagePrefix = "soroauth: c abi: panic: "

// Message turns a recovered panic value into the message the ABI puts in the
// error envelope. It is a plain function of (any) → string so it has no cgo
// dependency and can be tested without building the shared library.
//
// The message states a panic occurred and the string form of the value. It
// deliberately carries no stack: a stack in the caller's return value is a
// classic exfiltration channel, and the stack belongs in the process's own
// logs (debug.Stack(), written to stderr by the deferred recover in the ABI
// file) rather than in untrusted caller data. The function also strips any
// embedded newlines so the envelope stays a single JSON string even if the
// panic value was multi-line.
func Message(r any) string {
	raw := fmt.Sprintf("%v", r)
	return MessagePrefix + sanitise(raw)
}

// sanitise collapses any embedded newlines or carriage returns into a single
// space. A panic value that contains a stack-looking newline must not become
// a header-injection or log-forging opportunity in the caller's language.
func sanitise(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.TrimSpace(s)
}
