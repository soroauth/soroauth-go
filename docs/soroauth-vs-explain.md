# soroauth and soroauth-explain

The projects have deliberately different jobs and should be read together:

| Project                                                          | Responsibility                                                                                                          | Output                                                   |
| ---------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| [soroauth-go](https://github.com/soroauth/soroauth-go)           | Build, inspect, verify, sign, and submit Soroban authorization entries.                                                 | Go library, CLI, verification service, and integrations. |
| [soroauth-explain](https://github.com/soroauth/soroauth-explain) | Explain what an entry or transaction means to a human without pretending that an explanation is a verification verdict. | Human-facing interpretation and risk context.            |

Use soroauth-go when a program must produce or validate the bytes that will be
submitted. Use soroauth-explain when a person needs to understand those bytes
before approving them. An explanation is not a signature, and a successful
soroauth-go verification is not an endorsement of the transaction's business
intent.

## One entry through both tools

1. Obtain the unsigned or signed entry from the same simulation result.
2. Run `soroauth inspect --entry <base64>` or the Go verification API to decode
   the credential arm, invocation tree, expiration, and signatures. This is the
   machine-checkable step.
3. Give the same base64 entry (or the transaction envelope that contains it) to
   `soroauth-explain` for the human-readable interpretation. Preserve the
   network and ledger context it requests; an explanation without context can be
   misleading.
4. Show both results to the approver: the verifier's verdict and the explainer's
   description. Only after the user approves the meaning should the caller sign
   and submit through the normal two-pass flow.

The two tools must not silently rewrite each other's input. If a tool cannot
parse an entry, stop and report that fact instead of substituting a partial or
guessed explanation. See [the signing-flow guide](signing-flow.md) for why the
record and enforcing simulations must remain separate.

## Ownership boundary

Changes to signing bytes, XDR decoding, credential validation, CLI submission,
or verification belong in soroauth-go. Changes to wording, interpretation, human
approval context, or explain-only risk heuristics belong in soroauth-explain.
When a change crosses the boundary, update both repositories' README links and
keep the example above runnable with a committed fixture.
