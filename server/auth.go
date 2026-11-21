package main

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// Operation names an endpoint the authenticator may be asked about. It is a
// typed string rather than an untyped one so a typo in a scope string becomes
// a compile error, not a request that silently escapes a per-operation check.
//
// The verification service only reads entries, so the shipped operations are
// "verify" and "risk". A future endpoint that signs would add "sign" here; the
// issue text's "allowed to verify but not to sign" example maps cleanly onto
// that addition without shaking the interface. Operation names are stable and
// part of the authentication contract an operator configures.
type Operation string

const (
	// OpVerify is the scope POST /verify requires.
	OpVerify Operation = "verify"
	// OpRisk is the scope POST /risk requires.
	OpRisk Operation = "risk"
)

// Authenticator decides whether a request may invoke an operation. It is the
// pluggable boundary the issue asks for: one shipped implementation
// (bearerTokenAuthenticator) plus an interface so an operator who needs
// mTLS, OIDC or an in-house scheme writes a type that satisfies it rather
// than forking the service.
//
// A rejection returns an error that identifies the kind of failure
// (ErrUnauthenticated or ErrUnauthorized) but carries no information about
// the submitted request body: the handler writes a generic message and the
// request bytes are never read before this returns. The returned error's
// message is logged for the operator, never echoed to the caller.
type Authenticator interface {
	// Authenticate reads credentials from the request and returns the
	// identity it belongs to (opaque to the service), or an error. An
	// unauthenticated request returns ErrUnauthenticated; any other error
	// is treated as an authentication failure and logged for the operator.
	Authenticate(r *http.Request) (identity string, err error)
	// Authorize reports whether the identity may invoke op. Returning
	// ErrUnauthorized is the "authenticated but not permitted" case the
	// issue calls out; any other error is treated as unauthorized.
	Authorize(identity string, op Operation) error
}

// ErrUnauthenticated says the request carried no valid credential. The
// handler maps it to 401. A failure to parse a credential (malformed
// Authorization header) is also ErrUnauthenticated: a caller cannot tell
// "wrong format" from "wrong value" from the response, which is deliberate.
var ErrUnauthenticated = errors.New("unauthenticated")

// ErrUnauthorized says the request authenticated but the identity is not
// permitted to invoke this operation. The handler maps it to 403.
//
// The two errors are intentionally distinct: a caller who has the right
// credential but the wrong scope sees 403 and knows to ask for more access,
// rather than retrying with a different token that would also fail.
var ErrUnauthorized = errors.New("unauthorized")

// denyAll is the authenticator the server falls back to when configuration
// is incomplete. Fail-closed by construction: an unconfigured service refuses
// every request rather than serving a surprise open oracle.
//
// loadConfig keeps this unreachable in production — a non-loopback bind
// without AUTH_TOKEN is refused there, and a loopback bind installs
// openLoopbackAuthenticator — but a code path that forgot to set the
// authenticator still lands here instead of accidentally allowing requests.
type denyAll struct{}

func (denyAll) Authenticate(*http.Request) (string, error) {
	return "", ErrUnauthenticated
}

func (denyAll) Authorize(string, Operation) error {
	return ErrUnauthorized
}

// openLoopbackAuthenticator is the no-auth path loadConfig only permits on a
// loopback bind. It allows every operation, like the previous behaviour, and
// is named rather than represented by a nil interface so a caller inspecting
// s.cfg.Authenticator can see which path it took.
type openLoopbackAuthenticator struct{}

func (openLoopbackAuthenticator) Authenticate(*http.Request) (string, error) {
	return "loopback", nil
}

func (openLoopbackAuthenticator) Authorize(string, Operation) error {
	return nil
}

// bearerTokenAuthenticator is the shipped scheme. One shared secret per token
// grants a fixed set of operations. Multiple tokens may be configured, so a
// read-only CI pipeline can hold a token with only OpVerify while an
// on-call rotation holds a token with both operations.
//
// Lookups are constant-time per candidate token: a caller cannot recover a
// token by timing because every configured token is compared.
type bearerTokenAuthenticator struct {
	// tokens maps the full "Bearer <secret>" header value to the identity
	// label and the operations that identity may invoke. The header value
	// (not just the secret) is what subtle.ConstantTimeCompare takes, so
	// nothing in the hot path builds a transient string.
	tokens []tokenGrant
}

// tokenGrant is one row in bearerTokenAuthenticator.tokens.
type tokenGrant struct {
	// headerValue is the exact Authorization header the caller must send,
	// including "Bearer ". Keeping the prefix in the stored bytes is what
	// lets the lookup be one ConstantTimeCompare per candidate.
	headerValue []byte
	identity    string
	operations  map[Operation]struct{}
}

// newBearerTokenAuthenticator parses one or more tokens in the shape the
// AUTH_TOKEN environment variable carries. Legacy single-token form
// ("tok") grants every operation, so an existing deployment that only sets
// AUTH_TOKEN keeps working untouched. The richer form
// ("id1:tok1:verify,risk;id2:tok2:verify") assigns operations per token.
//
// Empty tokens are refused: an empty Authorization header must never match,
// and a configuration typo that leaves a token empty would silently become
// one if accepted.
func newBearerTokenAuthenticator(raw string) (*bearerTokenAuthenticator, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("AUTH_TOKEN is empty")
	}
	// Legacy single-token form: no delimiter at all means the whole string
	// is one shared secret with every operation.
	if !strings.ContainsAny(raw, ":;,") {
		return &bearerTokenAuthenticator{tokens: []tokenGrant{{
			headerValue: []byte("Bearer " + raw),
			identity:    "default",
			operations:  everyOperation(),
		}}}, nil
	}
	a := &bearerTokenAuthenticator{}
	for _, entry := range strings.Split(raw, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, ":", 3)
		if len(parts) < 2 {
			return nil, fmt.Errorf("AUTH_TOKEN entry %q: expected id:token or id:token:ops", entry)
		}
		id := strings.TrimSpace(parts[0])
		secret := strings.TrimSpace(parts[1])
		if id == "" || secret == "" {
			return nil, fmt.Errorf("AUTH_TOKEN entry %q: id and token must both be non-empty", entry)
		}
		ops := everyOperation()
		if len(parts) == 3 {
			ops = map[Operation]struct{}{}
			for _, op := range strings.Split(parts[2], ",") {
				op = strings.TrimSpace(op)
				if op == "" {
					continue
				}
				if !knownOperation(Operation(op)) {
					return nil, fmt.Errorf("AUTH_TOKEN entry %q: unknown operation %q (known: %s)",
						entry, op, strings.Join(knownOperationsSorted(), ", "))
				}
				ops[Operation(op)] = struct{}{}
			}
			if len(ops) == 0 {
				return nil, fmt.Errorf("AUTH_TOKEN entry %q: no operations granted; use %s to grant all",
					entry, strings.Join(knownOperationsSorted(), ","))
			}
		}
		a.tokens = append(a.tokens, tokenGrant{
			headerValue: []byte("Bearer " + secret),
			identity:    id,
			operations:  ops,
		})
	}
	if len(a.tokens) == 0 {
		return nil, errors.New("AUTH_TOKEN parsed to zero tokens")
	}
	return a, nil
}

// Authenticate finds the token the request bears, constant-time against every
// candidate. A match returns the identity the token was issued to; no match
// returns ErrUnauthenticated.
func (a *bearerTokenAuthenticator) Authenticate(r *http.Request) (string, error) {
	got := []byte(r.Header.Get("Authorization"))
	// Walk every configured token even after a match so the comparison time
	// does not depend on token order. The matched identity is remembered and
	// returned afterwards.
	matched := ""
	for _, t := range a.tokens {
		if subtle.ConstantTimeCompare(got, t.headerValue) == 1 && matched == "" {
			matched = t.identity
		}
	}
	if matched == "" {
		return "", ErrUnauthenticated
	}
	return matched, nil
}

// Authorize looks up the identity's grant row and reports whether op is in
// the operations it carries. An identity the authenticator did not issue
// returns ErrUnauthorized, which can only happen if the caller passes a
// handcrafted identity string.
func (a *bearerTokenAuthenticator) Authorize(identity string, op Operation) error {
	for _, t := range a.tokens {
		if t.identity != identity {
			continue
		}
		if _, ok := t.operations[op]; ok {
			return nil
		}
		return fmt.Errorf("%w: identity %q is not granted %q", ErrUnauthorized, identity, op)
	}
	return fmt.Errorf("%w: unknown identity %q", ErrUnauthorized, identity)
}

// authorize is the handler-side call: both Authenticate and Authorize in one
// place, with uniform mapping to HTTP status and a message that does not
// distinguish "no credential" from "wrong credential" from "wrong format".
// The operator still sees the detail in the structured request log.
func (s *server) authorize(w http.ResponseWriter, r *http.Request, op Operation) (identity string, ok bool) {
	auth := s.cfg.Authenticator
	if auth == nil {
		// Belt-and-braces: a server built without an authenticator refuses
		// every request. loadConfig installs one unconditionally, so this
		// path is unreachable in production; the nil check is what keeps
		// a future code path that forgot to set it from accidentally
		// opening the service.
		auth = denyAll{}
	}
	id, err := auth.Authenticate(r)
	if err != nil {
		s.writeError(w, r, http.StatusUnauthorized, "missing or invalid credential")
		s.cfg.Logger.Info("authentication failed", "op", string(op), "error", err.Error(), "remote", r.RemoteAddr)
		return "", false
	}
	if err := auth.Authorize(id, op); err != nil {
		// 403 so a correctly authenticated caller knows to ask for the
		// scope rather than retrying with a different credential.
		s.writeError(w, r, http.StatusForbidden, "credential is not permitted for this operation")
		s.cfg.Logger.Info("authorization failed", "op", string(op), "identity", id, "error", err.Error(), "remote", r.RemoteAddr)
		return "", false
	}
	return id, true
}

// knownOperation reports whether an operation name is one the service knows
// about. Guarding this in parsing keeps a typo in configuration ("verfy")
// from being silently rejected by Authorize.
func knownOperation(op Operation) bool {
	switch op {
	case OpVerify, OpRisk:
		return true
	}
	return false
}

// everyOperation returns a set containing every known operation. Used by the
// legacy single-token form which grants everything, so an existing deploy
// keeps working when it upgrades past this change.
func everyOperation() map[Operation]struct{} {
	return map[Operation]struct{}{
		OpVerify: {},
		OpRisk:   {},
	}
}

// knownOperationsSorted lists the known operations in a stable order so error
// messages are deterministic.
func knownOperationsSorted() []string {
	out := []string{string(OpVerify), string(OpRisk)}
	sort.Strings(out)
	return out
}

// authEnvVarDoc is embedded in the loadConfig error when AUTH_TOKEN fails to
// parse, so an operator discovers the richer syntax without reading the
// README during an outage.
const authEnvVarDoc = "AUTH_TOKEN accepts either a plain token (grants every operation) " +
	"or one or more id:token:ops entries separated by ';'. " +
	"Example: 'ci:abc123:verify;oncall:def456:verify,risk'."
