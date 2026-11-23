package opentelemetry

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// RenderTree renders finished spans as an indented tree, one line per span:
// name, duration, status, and attributes with the "soroauth." prefix trimmed.
// Children are ordered by start time, so the tree reads in the order the flow
// ran. It is how the example prints a trace to a terminal without a tracing
// backend; any OpenTelemetry exporter sees the same spans.
func RenderTree(spans []sdktrace.ReadOnlySpan) string {
	children := map[trace.SpanID][]sdktrace.ReadOnlySpan{}
	present := map[trace.SpanID]bool{}
	for _, s := range spans {
		present[s.SpanContext().SpanID()] = true
	}
	var roots []sdktrace.ReadOnlySpan
	for _, s := range spans {
		parent := s.Parent().SpanID()
		if s.Parent().IsValid() && present[parent] {
			children[parent] = append(children[parent], s)
			continue
		}
		roots = append(roots, s)
	}
	byStart := func(list []sdktrace.ReadOnlySpan) {
		sort.SliceStable(list, func(i, j int) bool { return list[i].StartTime().Before(list[j].StartTime()) })
	}
	byStart(roots)

	var b strings.Builder
	var walk func(s sdktrace.ReadOnlySpan, prefix string, last, root bool)
	walk = func(s sdktrace.ReadOnlySpan, prefix string, last, root bool) {
		branch, next := "", ""
		switch {
		case root:
		case last:
			branch, next = "└─ ", "   "
		default:
			branch, next = "├─ ", "│  "
		}
		fmt.Fprintf(&b, "%s%s%s  %s", prefix, branch, s.Name(), s.EndTime().Sub(s.StartTime()).Round(time.Millisecond))
		if s.Status().Code == codes.Error {
			fmt.Fprintf(&b, "  ERROR(%s)", s.Status().Description)
		}
		for _, kv := range s.Attributes() {
			fmt.Fprintf(&b, "  %s=%s", strings.TrimPrefix(string(kv.Key), "soroauth."), kv.Value.Emit())
		}
		b.WriteString("\n")
		kids := children[s.SpanContext().SpanID()]
		byStart(kids)
		for i, kid := range kids {
			walk(kid, prefix+next, i == len(kids)-1, false)
		}
	}
	for _, r := range roots {
		walk(r, "", true, true)
	}
	return b.String()
}
