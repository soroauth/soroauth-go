package soroauth

import (
	"strings"
	"testing"
)

func TestDelegateTreeASCII(t *testing.T) {
	tests := []struct {
		name string
		info EntryInfo
		want []string // substrings that must all appear, in order
	}{
		{
			name: "single node, no delegates",
			info: EntryInfo{
				CredentialType: CredentialTypeAddressV2,
				Address:        "GABC",
				TopLevelSigned: true,
			},
			want: []string{"GABC (signed) [address_v2]"},
		},
		{
			name: "unsigned top level",
			info: EntryInfo{
				CredentialType: CredentialTypeAddress,
				Address:        "GABC",
				TopLevelSigned: false,
			},
			want: []string{"GABC (unsigned) [address]"},
		},
		{
			name: "flat delegate list",
			info: EntryInfo{
				CredentialType: CredentialTypeAddressWithDelegates,
				Address:        "GTOP",
				TopLevelSigned: false,
				Delegates: []NodeInfo{
					{Address: "GA", Signed: true},
					{Address: "GB", Signed: false},
				},
			},
			want: []string{
				"GTOP (unsigned)",
				"├── GA (signed)",
				"└── GB (unsigned)",
			},
		},
		{
			name: "nested delegate",
			info: EntryInfo{
				CredentialType: CredentialTypeAddressWithDelegates,
				Address:        "GTOP",
				TopLevelSigned: true,
				Delegates: []NodeInfo{
					{
						Address: "GA",
						Signed:  true,
						Nested: []NodeInfo{
							{Address: "GNESTED", Signed: false},
						},
					},
				},
			},
			want: []string{
				"GTOP (signed)",
				"└── GA (signed)",
				"    └── GNESTED (unsigned)",
			},
		},
		{
			name: "same address at two depths is printed twice, not merged",
			info: EntryInfo{
				CredentialType: CredentialTypeAddressWithDelegates,
				Address:        "GTOP",
				Delegates: []NodeInfo{
					{
						Address: "GREPEAT",
						Signed:  true,
						Nested: []NodeInfo{
							{Address: "GREPEAT", Signed: false},
						},
					},
				},
			},
			want: []string{
				"└── GREPEAT (signed)",
				"    └── GREPEAT (unsigned)",
			},
		},
		{
			name: "empty address falls back to a placeholder",
			info: EntryInfo{
				CredentialType: CredentialTypeSourceAccount,
			},
			want: []string{"(no address) (unsigned) [source_account]"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DelegateTreeASCII(tt.info)
			for _, want := range tt.want {
				if !strings.Contains(got, want) {
					t.Errorf("DelegateTreeASCII output missing %q\ngot:\n%s", want, got)
				}
			}
		})
	}
}

// TestDelegateTreeASCII_RepeatedAddressCountsMatch proves the "printed twice"
// claim precisely, rather than only by substring: an address that appears at
// two nesting levels must appear exactly twice in the rendered tree, once per
// occurrence, not once because it was deduplicated.
func TestDelegateTreeASCII_RepeatedAddressCountsMatch(t *testing.T) {
	info := EntryInfo{
		CredentialType: CredentialTypeAddressWithDelegates,
		Address:        "GTOP",
		Delegates: []NodeInfo{
			{
				Address: "GREPEAT",
				Signed:  true,
				Nested: []NodeInfo{
					{Address: "GREPEAT", Signed: false},
				},
			},
			{Address: "GREPEAT", Signed: false},
		},
	}
	got := DelegateTreeASCII(info)
	count := strings.Count(got, "GREPEAT")
	if count != 3 {
		t.Errorf("expected GREPEAT to appear 3 times (once per occurrence), got %d in:\n%s", count, got)
	}
}

func TestDelegateTreeDOT(t *testing.T) {
	info := EntryInfo{
		CredentialType: CredentialTypeAddressWithDelegates,
		Address:        "GTOP",
		TopLevelSigned: true,
		Delegates: []NodeInfo{
			{
				Address: "GA",
				Signed:  true,
				Nested: []NodeInfo{
					{Address: "GA", Signed: false}, // same address, deeper level
				},
			},
			{Address: "GB", Signed: false},
		},
	}

	got := DelegateTreeDOT(info)

	if !strings.HasPrefix(got, "digraph delegates {") {
		t.Errorf("expected a digraph header, got:\n%s", got)
	}
	if !strings.HasSuffix(strings.TrimSpace(got), "}") {
		t.Errorf("expected the digraph to be closed, got:\n%s", got)
	}

	// Every node gets a distinct synthetic ID, so the two "GA" occurrences
	// (different depths) must not collapse into one node or one edge.
	for _, want := range []string{
		`n0 [label="GTOP"`,
		`n0_0 [label="GA"`,
		`n0_0_0 [label="GA"`,
		`n0_1 [label="GB"`,
		"n0 -> n0_0;",
		"n0_0 -> n0_0_0;",
		"n0 -> n0_1;",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("DelegateTreeDOT output missing %q\ngot:\n%s", want, got)
		}
	}

	if strings.Count(got, `label="GA"`) != 2 {
		t.Errorf("expected two distinct GA nodes, got:\n%s", got)
	}
}

func TestDelegateTreeDOT_EmptyAddressPlaceholder(t *testing.T) {
	got := DelegateTreeDOT(EntryInfo{CredentialType: CredentialTypeSourceAccount})
	if !strings.Contains(got, `label="(no address)"`) {
		t.Errorf("expected a placeholder label for an empty address, got:\n%s", got)
	}
}
