package soroauth

import (
	"fmt"
	"strings"
)

// DelegateTreeASCII renders info's credential tree as an indented ASCII tree
// for a terminal, one line per node, each line saying whether that node
// carries a signature.
//
// The top-level node is always shown, since every credentials arm has one;
// the delegates arm (issue #90's motivating case) adds NodeInfo children
// beneath it. One address appearing at more than one depth is not
// deduplicated or flagged as a cycle: CAP-71-01 permits the same address at
// different nesting levels, and each occurrence is a distinct node with its
// own signature, so it is printed once per occurrence, in its own position in
// the tree.
func DelegateTreeASCII(info EntryInfo) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s%s\n", treeLabel(info.Address, info.TopLevelSigned), treeSuffix(info))
	writeASCIINodes(&b, info.Delegates, "")
	return b.String()
}

// treeSuffix reports the credential arm inline on the root line, since a
// non-delegates entry has no children to otherwise distinguish it in the
// tree.
func treeSuffix(info EntryInfo) string {
	if info.CredentialType == CredentialTypeAddressWithDelegates {
		return ""
	}
	return " [" + info.CredentialType + "]"
}

func treeLabel(address string, signed bool) string {
	status := "unsigned"
	if signed {
		status = "signed"
	}
	if address == "" {
		address = "(no address)"
	}
	return fmt.Sprintf("%s (%s)", address, status)
}

// writeASCIINodes writes one level of the delegate tree beneath prefix, using
// the box-drawing connectors a terminal `tree` command uses: "├──" for every
// sibling but the last, "└──" for the last, and "│   " continuing the
// ancestor's vertical line for a sibling that still has more entries after
// it.
func writeASCIINodes(b *strings.Builder, nodes []NodeInfo, prefix string) {
	for i, node := range nodes {
		last := i == len(nodes)-1
		connector := "├── "
		nextPrefix := prefix + "│   "
		if last {
			connector = "└── "
			nextPrefix = prefix + "    "
		}
		fmt.Fprintf(b, "%s%s%s\n", prefix, connector, treeLabel(node.Address, node.Signed))
		writeASCIINodes(b, node.Nested, nextPrefix)
	}
}

// DelegateTreeDOT renders info's credential tree as a Graphviz DOT digraph,
// for embedding in documentation. Every node gets a synthetic, positional ID
// (n0, n0_0, n0_1, ...) distinct from its address, precisely so that the same
// address at two different nesting levels — legal under CAP-71-01 and the
// case this renderer exists to make unambiguous — draws as two separate
// nodes rather than being collapsed into one by a shared ID. A signed node is
// filled green; an unsigned one is filled white with a grey outline.
func DelegateTreeDOT(info EntryInfo) string {
	var b strings.Builder
	b.WriteString("digraph delegates {\n")
	b.WriteString("  rankdir=TB;\n")
	b.WriteString("  node [shape=box, fontname=\"monospace\"];\n\n")

	rootID := "n0"
	writeDOTNode(&b, rootID, info.Address, info.TopLevelSigned)
	writeDOTNodes(&b, rootID, info.Delegates)

	b.WriteString("}\n")
	return b.String()
}

func writeDOTNode(b *strings.Builder, id, address string, signed bool) {
	if address == "" {
		address = "(no address)"
	}
	fill, color := "white", "grey60"
	if signed {
		fill, color = "palegreen3", "palegreen4"
	}
	fmt.Fprintf(b, "  %s [label=%q, style=filled, fillcolor=%q, color=%q];\n", id, address, fill, color)
}

func writeDOTNodes(b *strings.Builder, parentID string, nodes []NodeInfo) {
	for i, node := range nodes {
		id := fmt.Sprintf("%s_%d", parentID, i)
		writeDOTNode(b, id, node.Address, node.Signed)
		fmt.Fprintf(b, "  %s -> %s;\n", parentID, id)
		writeDOTNodes(b, id, node.Nested)
	}
}
