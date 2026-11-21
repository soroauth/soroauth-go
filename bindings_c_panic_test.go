package soroauth_test

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestCExportsHavePanicGuard enumerates every //export in bindings/c/soroauth.go
// and asserts each function body defers a panicguard. A panic that unwinds
// through cgo takes the host process with it; this guard is what keeps a
// Node/JVM/Python/Rust host alive when the library panics, and this test is
// what keeps the guard honest as new //exports are added.
//
// The assertion is deliberately static — it reads the Go source rather than
// building the C shared library — so it runs under the required ci vet+test
// workflow which has no C toolchain.
func TestCExportsHavePanicGuard(t *testing.T) {
	src, err := os.ReadFile("bindings/c/soroauth.go")
	if err != nil {
		t.Fatalf("reading bindings/c/soroauth.go: %v", err)
	}

	exportRe := regexp.MustCompile(`(?m)^//export (\w+)$`)
	matches := exportRe.FindAllSubmatchIndex(src, -1)
	if len(matches) == 0 {
		t.Fatal("no //export directives found; the regex or the file moved")
	}

	// Each //export at index i runs until the next //export or end of file.
	// The function body inside that window must defer one of the three
	// panicguard variants. Index 1 of the match is where the directive ends
	// (the newline before the next line).
	deferRe := regexp.MustCompile(`defer catchPanic(Int|Void)?\(`)
	for i, m := range matches {
		name := string(src[m[2]:m[3]])
		bodyStart := m[1]
		bodyEnd := len(src)
		if i+1 < len(matches) {
			bodyEnd = matches[i+1][0]
		}
		body := src[bodyStart:bodyEnd]
		if !deferRe.Match(body) {
			t.Errorf("//export %s has no `defer catchPanic...` guard in its body", name)
		}
	}
}

// TestCExportsNamedReturn asserts every //export has a named return value (or
// is void), because the deferred catchPanic needs to assign to it. A plain
// `func X() *C.char` silently defeats the recover: the deferred function has
// no way to replace the return value, so a panic would still unwind through
// cgo.
func TestCExportsNamedReturn(t *testing.T) {
	src, err := os.ReadFile("bindings/c/soroauth.go")
	if err != nil {
		t.Fatalf("reading bindings/c/soroauth.go: %v", err)
	}

	// Match "//export Name\nfunc Name(args) [return-spec] {"
	// The capture group pins the return spec so we can inspect it.
	sigRe := regexp.MustCompile(`(?m)^//export (\w+)\nfunc \w+\([^)]*\)\s*([^{]*)\{`)
	matches := sigRe.FindAllSubmatch(src, -1)
	if len(matches) == 0 {
		t.Fatal("no //export + func lines matched; the regex or the file moved")
	}

	for _, m := range matches {
		name := string(m[1])
		returnSpec := strings.TrimSpace(string(m[2]))
		switch returnSpec {
		case "":
			// void return — OK, catchPanicVoid does not need a named return.
			continue
		}
		if !strings.HasPrefix(returnSpec, "(") || !strings.HasSuffix(returnSpec, ")") {
			t.Errorf("//export %s has return spec %q, want a named parenthesised return so defer catchPanic can overwrite it", name, returnSpec)
		}
	}
}
