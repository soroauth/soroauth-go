package soroauth_test

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestCHeaderMatchesExports(t *testing.T) {
	goSrc, err := os.ReadFile("bindings/c/soroauth.go")
	if err != nil {
		t.Fatalf("reading bindings/c/soroauth.go: %v", err)
	}
	header, err := os.ReadFile("bindings/c/libsoroauth.h")
	if err != nil {
		t.Fatalf("reading bindings/c/libsoroauth.h: %v", err)
	}

	exportRe := regexp.MustCompile(`(?m)^//export (\w+)$`)
	matches := exportRe.FindAllStringSubmatch(string(goSrc), -1)
	if len(matches) == 0 {
		t.Fatal("found no //export directives in soroauth.go")
	}
	goExports := make(map[string]bool, len(matches))
	for _, m := range matches {
		goExports[m[1]] = true
	}

	declRe := regexp.MustCompile(`(?m)^\w[\w* ]*\b(\w+)\s*\(`)
	headerText := string(header)
	var headerLines []string
	for _, line := range strings.Split(headerText, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "/*") ||
			strings.HasPrefix(trimmed, "*") || strings.HasPrefix(trimmed, "//") ||
			strings.HasPrefix(trimmed, "#") {
			continue
		}
		headerLines = append(headerLines, trimmed)
	}

	headerFuncs := make(map[string]bool)
	for _, line := range headerLines {
		m := declRe.FindStringSubmatch(line)
		if m != nil {
			headerFuncs[m[1]] = true
		}
	}

	if len(headerFuncs) == 0 {
		t.Fatal("found no function declarations in libsoroauth.h")
	}

	goNames := sortedKeys(goExports)
	headerNames := sortedKeys(headerFuncs)

	for _, name := range goNames {
		if !headerFuncs[name] {
			t.Errorf("//export %s in soroauth.go has no declaration in libsoroauth.h", name)
		}
	}
	for _, name := range headerNames {
		if !goExports[name] {
			t.Errorf("libsoroauth.h declares %s but soroauth.go has no //export for it", name)
		}
	}

	if t.Failed() {
		t.Logf("Go exports:   %v", goNames)
		t.Logf("Header funcs: %v", headerNames)
	}
}

func TestCHeaderNoCgoInternalTypes(t *testing.T) {
	header, err := os.ReadFile("bindings/c/libsoroauth.h")
	if err != nil {
		t.Fatalf("reading bindings/c/libsoroauth.h: %v", err)
	}

	forbidden := []string{"GoInt", "GoString", "GoSlice", "GoFloat", "GoUint", "GoComplex", "_GoString_"}
	for _, typ := range forbidden {
		if strings.Contains(string(header), typ) {
			t.Errorf("header contains cgo-internal type %q", typ)
		}
	}
}

func TestCHeaderHasAbiVersion(t *testing.T) {
	header, err := os.ReadFile("bindings/c/libsoroauth.h")
	if err != nil {
		t.Fatalf("reading bindings/c/libsoroauth.h: %v", err)
	}

	if !strings.Contains(string(header), "SOROAUTH_ABI_VERSION") {
		t.Error("header is missing SOROAUTH_ABI_VERSION macro")
	}
	if !strings.Contains(string(header), "SoroauthAbiVersion") {
		t.Error("header is missing SoroauthAbiVersion function declaration")
	}
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
