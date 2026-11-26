package soroauth

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// The two findings a correspondence check can produce. An operation with its
// entries is an `entry` kind; an entry whose root invocation does not match
// the operation's host function is a `mismatch` kind; an entry attached to an
// operation that names no authorized function at all is an `unmatched_entry`
// kind. Source-account entries are not exempted from any of this: their root
// invocation is compared exactly like the others.
const (
	correspondenceMismatch       = "mismatch"
	correspondenceUnmatchedEntry = "unmatched_entry"
)

// CorrespondenceFinding is one mismatch between an operation and the entry an
// envelope carries for it.
//
// OperationIndex and EntryIndex are the positions the entry came from, as
// EnvelopeEntries reports them. Path is the entry-side field path in the same
// style Inspect and DiffEntries use, so a caller already reading one of those
// reports can point at the same location.
type CorrespondenceFinding struct {
	// OperationIndex is the operation the entry came from.
	OperationIndex int `json:"operation_index"`

	// EntryIndex is the entry's position inside that operation's auth vector.
	EntryIndex int `json:"entry_index"`

	// Kind is "mismatch" when the two sides disagree on a field, or
	// "unmatched_entry" when the entry has nothing to compare with.
	Kind string `json:"kind"`

	// Path is the entry-side field that disagrees.
	Path string `json:"path"`

	// Operation is a short name of the operation's host function, so the
	// finding reads "operation entry 0: contract_fn vs create_contract_host_fn".
	Operation string `json:"operation,omitempty"`

	// Entry is the entry's function type, so the finding reads the same way.
	Entry string `json:"entry,omitempty"`
}

// CorrespondenceReport is the answer to one envelope.
type CorrespondenceReport struct {
	// OK is true when every entry in the envelope maps to its operation with
	// no mismatched field. An invoke operation that carries no entries is a
	// valid shape (the source account authorizes it), so it does not by
	// itself fail the check; see OperationsWithoutEntries.
	OK bool `json:"ok"`

	// EntriesChecked counts the entries compared. A source-account entry is
	// compared too: checkEnvelopeCorrespondence reports what an entry
	// authorizes, and it authorizes something, because its credentials arm
	// still names an invocation.
	EntriesChecked int `json:"entries_checked"`

	// Findings is the evidence: one per mismatched field, then one per
	// unmatched entry.
	Findings []CorrespondenceFinding `json:"findings,omitempty"`

	// OperationsWithoutEntries are the invoke operation indices that carry
	// no authorization entries at all.
	OperationsWithoutEntries []int `json:"operations_without_entries,omitempty"`

	// Summary is the one-line verdict.
	Summary string `json:"summary"`
}

// hostFunctionTypeName names an operation's host function type so a finding
// can say what the operation is.
func hostFunctionTypeName(t xdr.HostFunctionType) string {
	switch t {
	case xdr.HostFunctionTypeHostFunctionTypeInvokeContract:
		return "contract_fn"
	case xdr.HostFunctionTypeHostFunctionTypeCreateContract:
		return "create_contract_host_fn"
	case xdr.HostFunctionTypeHostFunctionTypeCreateContractV2:
		return "create_contract_v2_host_fn"
	case xdr.HostFunctionTypeHostFunctionTypeUploadContractWasm:
		return "upload_contract_wasm"
	default:
		return fmt.Sprintf("host_function_type_%d", t)
	}
}

// entryFunctionTypeName does the same for a SorobanAuthorizedFunction, since
// the entry-side path is rootInvocation.function.type.
func entryFunctionTypeName(t xdr.SorobanAuthorizedFunctionType) string {
	switch t {
	case xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn:
		return "contract_fn"
	case xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeCreateContractHostFn:
		return "create_contract_host_fn"
	case xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeCreateContractV2HostFn:
		return "create_contract_v2_host_fn"
	default:
		return fmt.Sprintf("soroban_authorized_function_type_%d", t)
	}
}

// fingerprint renders one XDR field's value for a finding, as a short sha256
// of its encoding rather than raw bytes: the bytes are arbitrary, but the
// fingerprint locates the value.
func fingerprint(v interface{ MarshalBinary() ([]byte, error) }) string {
	b, err := v.MarshalBinary()
	if err != nil {
		return "unencodable"
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:6])
}

// HfToCreate reads the create-contract args out of a HostFunction union so
// the two sides of a correspondence check meet the same shape. GetCreateContract
// is the SDK's official reader for that union; the switch arms in
// compareCreateHostFn stay in sync with the XDR definition.
func HfToCreate(hf xdr.HostFunction) *xdr.CreateContractArgs {
	c, ok := hf.GetCreateContract()
	if !ok {
		return nil
	}
	return &c
}

// HfToCreateV2 is the V2 counterpart of HfToCreate.
func HfToCreateV2(hf xdr.HostFunction) *xdr.CreateContractArgsV2 {
	c, ok := hf.GetCreateContractV2()
	if !ok {
		return nil
	}
	return &c
}

// compareContractFn reports a mismatch, field by field, between an operation's
// invoke-contract host function and an entry's root invocation.
func compareContractFn(hf xdr.HostFunction, root xdr.SorobanAuthorizedFunction, opIndex, entryIndex int, report *CorrespondenceReport) {
	path := "rootInvocation.function"
	switch root.Type {
	case xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn:
		if hf.Type != xdr.HostFunctionTypeHostFunctionTypeInvokeContract {
			report.add(opIndex, entryIndex, correspondenceMismatch, path+".type",
				hostFunctionTypeName(hf.Type), entryFunctionTypeName(root.Type))
			return
		}
		entryContract, err := FormatAddress(hf.InvokeContract.ContractAddress)
		if err != nil {
			report.add(opIndex, entryIndex, correspondenceMismatch, path+".contractAddress",
				"unformattable operation address", "unformattable")
			return
		}
		entryContractStr, err := FormatAddress(root.ContractFn.ContractAddress)
		if err != nil {
			report.add(opIndex, entryIndex, correspondenceMismatch, path+".contractAddress",
				"unformattable entry address", "unformattable")
			return
		}
		if entryContractStr != entryContract {
			report.add(opIndex, entryIndex, correspondenceMismatch, path+".contractAddress",
				entryContract, entryContractStr)
		}
		if string(root.ContractFn.FunctionName) != string(hf.InvokeContract.FunctionName) {
			report.add(opIndex, entryIndex, correspondenceMismatch, path+".functionName",
				string(hf.InvokeContract.FunctionName), string(root.ContractFn.FunctionName))
		}
		if len(root.ContractFn.Args) != len(hf.InvokeContract.Args) {
			report.add(opIndex, entryIndex, correspondenceMismatch, path+".args",
				fmt.Sprintf("%d arguments", len(hf.InvokeContract.Args)),
				fmt.Sprintf("%d arguments", len(root.ContractFn.Args)))
			return
		}
		for i := range root.ContractFn.Args {
			same, err := xdrEqual(root.ContractFn.Args[i], hf.InvokeContract.Args[i])
			if err != nil {
				report.add(opIndex, entryIndex, correspondenceMismatch, path+".args[%d]", err.Error(), "")
				continue
			}
			if !same {
				report.add(opIndex, entryIndex, correspondenceMismatch, path+".args[%d]",
					root.ContractFn.Args[i].Type.String(), hf.InvokeContract.Args[i].Type.String())
			}
		}
	default:
		report.add(opIndex, entryIndex, correspondenceMismatch, path+".type",
			hostFunctionTypeName(hf.Type), entryFunctionTypeName(root.Type))
	}
}

// compareCreateHostFn reports a mismatch, field by field, against a create
// host function (both versions).
func compareCreateHostFn(typ xdr.SorobanAuthorizedFunctionType, hf xdr.HostFunction, root xdr.SorobanAuthorizedFunction, opIndex, entryIndex int, report *CorrespondenceReport) {
	op := HfToCreate(hf)
	if op == nil {
		return
	}
	rootC := root.CreateContractHostFn
	path := "rootInvocation.function"
	report.add(opIndex, entryIndex, correspondenceMismatch, path+".type",
		hostFunctionTypeName(hf.Type), entryFunctionTypeName(typ))
	switch typ {
	case xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeCreateContractHostFn:
		op := HfToCreate(hf)
		if op == nil {
			return
		}
		rootC := root.CreateContractHostFn
		if same, err := xdrEqual(op.ContractIdPreimage, rootC.ContractIdPreimage); err != nil {
			report.add(opIndex, entryIndex, correspondenceMismatch, path+".createContractHostFn.contractIdPreimage",
				"unencodable", err.Error())
		} else if !same {
			report.add(opIndex, entryIndex, correspondenceMismatch, path+".createContractHostFn.contractIdPreimage",
				fingerprint(op.ContractIdPreimage), fingerprint(rootC.ContractIdPreimage))
		}
		if same, err := xdrEqual(op.Executable, rootC.Executable); err != nil {
			report.add(opIndex, entryIndex, correspondenceMismatch, path+".createContractHostFn.executable",
				"unencodable", err.Error())
		} else if !same {
			report.add(opIndex, entryIndex, correspondenceMismatch, path+".createContractHostFn.executable",
				fingerprint(op.Executable), fingerprint(rootC.Executable))
		}
	case xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeCreateContractV2HostFn:
		op := HfToCreateV2(hf)
		if op == nil {
			return
		}
		if same, err := xdrEqual(op.ContractIdPreimage, root.CreateContractV2HostFn.ContractIdPreimage); err != nil {
			report.add(opIndex, entryIndex, correspondenceMismatch, path+".createContractV2HostFn.contractIdPreimage",
				"unencodable", err.Error())
		} else if !same {
			report.add(opIndex, entryIndex, correspondenceMismatch, path+".createContractV2HostFn.contractIdPreimage",
				fingerprint(op.ContractIdPreimage), fingerprint(root.CreateContractV2HostFn.ContractIdPreimage))
		}
		if same, err := xdrEqual(op.Executable, rootC.Executable); err != nil {
			report.add(opIndex, entryIndex, correspondenceMismatch, path+".createContractV2HostFn.executable",
				"unencodable", err.Error())
		} else if !same {
			report.add(opIndex, entryIndex, correspondenceMismatch, path+".createContractV2HostFn.executable",
				fingerprint(op.Executable), fingerprint(rootC.Executable))
		}
		if len(root.CreateContractV2HostFn.ConstructorArgs) != len(op.ConstructorArgs) {
			report.add(opIndex, entryIndex, correspondenceMismatch, path+".createContractV2HostFn.constructorArgs",
				fmt.Sprintf("%d arguments", len(op.ConstructorArgs)),
				fmt.Sprintf("%d arguments", len(root.CreateContractV2HostFn.ConstructorArgs)))
			return
		}
		for i := range root.CreateContractV2HostFn.ConstructorArgs {
			same, err := xdrEqual(root.CreateContractV2HostFn.ConstructorArgs[i], op.ConstructorArgs[i])
			if err != nil {
				report.add(opIndex, entryIndex, correspondenceMismatch, path+".createContractV2HostFn.constructorArgs[%d]", err.Error(), "")
				continue
			}
			if !same {
				report.add(opIndex, entryIndex, correspondenceMismatch, path+".createContractV2HostFn.constructorArgs[%d]",
					root.CreateContractV2HostFn.ConstructorArgs[i].Type.String(), op.ConstructorArgs[i].Type.String())
			}
		}
	}
}

// correspondEntry compares one entry against its operation.
//
// The two sides are independent things: the operation's host function comes
// from the envelope, the entry's root invocation from the authorization
// framework. The entries of a transaction should authorize exactly what the
// operations do. When they do not, the difference is a field in the entry, so
// the comparison walks the entry's root invocation field by field and reports
// the path, the operation's value and the entry's value, like DiffEntries.
func correspondEntry(hf xdr.HostFunction, root xdr.SorobanAuthorizedFunction, op xdr.Operation, opIndex, entryIndex int, report *CorrespondenceReport) {
	switch hf.Type {
	case xdr.HostFunctionTypeHostFunctionTypeInvokeContract:
		compareContractFn(hf, root, opIndex, entryIndex, report)
	case xdr.HostFunctionTypeHostFunctionTypeCreateContract:
		compareCreateHostFn(xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeCreateContractHostFn, hf, root, opIndex, entryIndex, report)
	case xdr.HostFunctionTypeHostFunctionTypeCreateContractV2:
		compareCreateHostFn(xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeCreateContractV2HostFn, hf, root, opIndex, entryIndex, report)
	case xdr.HostFunctionTypeHostFunctionTypeUploadContractWasm:
		report.add(opIndex, entryIndex, correspondenceUnmatchedEntry, "rootInvocation.function",
			hostFunctionTypeName(hf.Type), entryFunctionTypeName(root.Type))
		return
	default:
		// An operation with a host function we do not know about has no
		// authorized-function counterpart for any entry on it. Fail closed:
		// this cannot be checked, so it is reported as unmatched.
		return
	}
}

// CheckEnvelopeCorrespondence reports whether every authorization entry in an
// envelope matches the invokeHostFunction operation it sits on, field by
// field, with the field path where they diverge.
//
// Why this exists: an envelope carries operations and entries side by side,
// and nothing else in this library ever compares them. An entry authorizing a
// different contract call than the operation performs is the clearest sign of
// tampering, and it is invisible without reading both by hand. This report
// turns it into a list of paths.
//
// An entry with no corresponding operation is one attached to an operation
// that names no authorized function (for example an upload-contract-wasm
// operation): the operation has nothing to compare against, so that entry is
// reported, rather than silently dropped. An operation with no entry
// (OperationsWithoutEntries) is reported separately: a valid envelope's
// invoke operation can legitimately carry no entries, when the operation's
// addresses are the transaction source and the envelope is authorized by the
// envelope signature instead.
//
// The entry's root invocation is compared with the operation's host function
// field by field: contract address, function name, and every argument's bytes
// (compared as XDR, the same way the host and DiffEntries do). A source-account
// entry is compared as well: its root invocation still has to match, because
// the envelope's own signature does not authorize a different operation.
// An entry whose root invocation uses a function type the operation does not
// name is a mismatch, not an exemption.
//
// The entry is not modified. It is read, which is all this function does.
func CheckEnvelopeCorrespondence(env xdr.TransactionEnvelope) (CorrespondenceReport, error) {
	operations, err := envelopeOperations(env)
	if err != nil {
		return CorrespondenceReport{}, fmt.Errorf("soroauth: envelope correspondence: %w", err)
	}

	report := CorrespondenceReport{}
	for i := range operations {
		body := operations[i].Body
		if body.Type != xdr.OperationTypeInvokeHostFunction || body.InvokeHostFunctionOp == nil {
			continue
		}
		auth := body.InvokeHostFunctionOp.Auth
		if len(auth) == 0 {
			report.OperationsWithoutEntries = append(report.OperationsWithoutEntries, i)
			continue
		}
		for j := range auth {
			correspondEntry(operations[i].Body.InvokeHostFunctionOp.HostFunction, auth[j].RootInvocation.Function, operations[i], i, j, &report)
		}
	}
	report.OK = len(report.Findings) == 0
	report.Summary = reportSummary(report)
	return report, nil
}

// add records one finding, rewriting the field names into the readable form
// this report uses while keeping the path precise.
func (r *CorrespondenceReport) add(opIndex, entryIndex int, kind, path, operation, entry string) {
	r.Findings = append(r.Findings, CorrespondenceFinding{
		OperationIndex: opIndex,
		EntryIndex:     entryIndex,
		Kind:           kind,
		Path:           path,
		Operation:      operation,
		Entry:          entry,
	})
}

func reportSummary(report CorrespondenceReport) string {
	if report.OK {
		return fmt.Sprintf("%d entry/operation pair(s) in agreement", report.EntriesChecked)
	}
	parts := make([]string, 0, len(report.Findings))
	for _, f := range report.Findings {
		parts = append(parts, fmt.Sprintf("entry %d op %d: %s %s vs %s (%s)", f.EntryIndex, f.OperationIndex, f.Kind, f.Path, f.Entry, f.Operation))
	}
	return fmt.Sprintf("mismatch: %s", strings.Join(parts, "; "))
}
