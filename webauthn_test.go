package soroauth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// b64urlRaw and b64urlPadded are the two base64url spellings real serializers
// emit (WebAuthn Level 2 §5.1.4 says unpadded; several libraries pad anyway).
func b64urlRaw(b []byte) string    { return base64.RawURLEncoding.EncodeToString(b) }
func b64urlPadded(b []byte) string { return base64.URLEncoding.EncodeToString(b) }

// webAuthnFixture builds a serialized PublicKeyCredential with the given
// base64url (or, where a test deliberately corrupts it, arbitrary) fields.
// Passing "" for a field makes it absent from the JSON, which is how the
// missing-field cases are expressed.
func webAuthnFixture(credentialType, clientDataJSON, authenticatorData, signature string) []byte {
	body := map[string]any{
		"id":    "test-credential-id",
		"rawId": "dGVzdC1jcmVkZW50aWFsLWlk",
		"type":  credentialType,
		"response": map[string]any{
			"clientDataJSON":    clientDataJSON,
			"authenticatorData": authenticatorData,
			"signature":         signature,
			"userHandle":        nil,
		},
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	return encoded
}

// clientData builds the JSON the browser signs over. Only the members the
// parser reads are set; the rest of the shape is irrelevant to it.
func clientData(challenge string) []byte {
	body := map[string]any{
		"type":        "webauthn.get",
		"challenge":   challenge,
		"origin":      "https://soroauth.example",
		"crossOrigin": false,
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	return encoded
}

// authenticatorData builds authenticator data with the given flags and
// signCount. The RP ID hash is the SHA-256 of the origin the client data
// names, as a real browser leaf would produce (WebAuthn Level 2 §6.1).
func authenticatorData(flags byte, signCount uint32) []byte {
	rpIDHash := sha256.Sum256([]byte("https://soroauth.example"))
	data := make([]byte, 0, authDataMinLen)
	data = append(data, rpIDHash[:]...)
	data = append(data, flags)
	data = append(data, byte(signCount>>24), byte(signCount>>16), byte(signCount>>8), byte(signCount))
	return data
}

// realAssertion is a captured-shape assertion: full-length authenticator data
// (RP ID hash, flags with UP and UV set, sign counter), a 64-byte P-256
// signature and a base64url challenge. It is the input a passkey wallet's
// browser ceremony hands a backend, minus the private key that produced the
// signature, which the parser does not need.
//
// The bytes are deterministic so the fixture is reproducible; see
// TestParseWebAuthnAssertionRealAuthenticatorFixture, which documents where the
// shape comes from.
func realAssertion(payload [32]byte) []byte {
	clientDataJSON := clientData(b64urlRaw(payload[:]))
	signature := make([]byte, 64)
	for i := range signature {
		signature[i] = byte(i + 1)
	}
	return webAuthnFixture("public-key", b64urlRaw(clientDataJSON),
		b64urlRaw(authenticatorData(flagUserPresent|flagUserVerified, 42)), b64urlRaw(signature))
}

func webAuthnPayload() [32]byte {
	return sha256.Sum256([]byte("soroauth webauthn test payload"))
}

// TestParseWebAuthnAssertionRealAuthenticatorFixture parses a complete
// assertion of the shape a real authenticator produces: 37+ bytes of
// authenticator data, clientDataJSON and a signature, all base64url.
//
// The layout is WebAuthn Level 2 §5.1.4 (serialization) and §6.1
// (authenticator data), and the fixture is built deterministically rather than
// captured live so it regenerates exactly; the parser tests below add the
// deliberately malformed variants a capture cannot cover on demand.
func TestParseWebAuthnAssertionRealAuthenticatorFixture(t *testing.T) {
	payload := webAuthnPayload()
	raw := realAssertion(payload)

	assertion, err := ParseWebAuthnAssertionForPayload(raw, payload)
	if err != nil {
		t.Fatalf("ParseWebAuthnAssertionForPayload: %v", err)
	}

	if len(assertion.AuthenticatorData) != authDataMinLen {
		t.Errorf("authenticatorData length = %d, want %d", len(assertion.AuthenticatorData), authDataMinLen)
	}
	if !assertion.UserPresent() {
		t.Error("UserPresent() = false, want true")
	}
	if !assertion.UserVerified() {
		t.Error("UserVerified() = false, want true")
	}
	if assertion.Flags() != flagUserPresent|flagUserVerified {
		t.Errorf("Flags() = 0x%02x, want 0x%02x", assertion.Flags(), flagUserPresent|flagUserVerified)
	}
	if len(assertion.Signature) != 64 {
		t.Errorf("signature length = %d, want 64", len(assertion.Signature))
	}
	if got := string(assertion.ClientDataJSON); !strings.Contains(got, "webauthn.get") {
		t.Errorf("clientDataJSON = %q, want it to carry the webauthn.get type", got)
	}
	if err := assertion.VerifyChallenge(payload[:]); err != nil {
		t.Errorf("VerifyChallenge(payload) = %v, want nil", err)
	}
}

func TestParseWebAuthnAssertionValidChallengeEncodings(t *testing.T) {
	payload := webAuthnPayload()
	sig := b64urlRaw([]byte{1, 2, 3, 4})

	tests := []struct {
		name      string
		challenge string
	}{
		{"unpadded base64url", b64urlRaw(payload[:])},
		{"padded base64url", b64urlPadded(payload[:])},
		{"unpadded standard base64", base64.RawStdEncoding.EncodeToString(payload[:])},
		{"padded standard base64", base64.StdEncoding.EncodeToString(payload[:])},
		{"lowercase hex", hex.EncodeToString(payload[:])},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := webAuthnFixture("public-key",
				b64urlRaw(clientData(tt.challenge)),
				b64urlRaw(authenticatorData(flagUserPresent, 7)),
				sig)
			assertion, err := ParseWebAuthnAssertionForPayload(raw, payload)
			if err != nil {
				t.Fatalf("ParseWebAuthnAssertionForPayload: %v", err)
			}
			if err := assertion.VerifyChallenge(payload[:]); err != nil {
				t.Errorf("VerifyChallenge(payload) = %v, want nil", err)
			}
			if assertion.ChallengeString != tt.challenge {
				t.Errorf("ChallengeString = %q, want %q", assertion.ChallengeString, tt.challenge)
			}
		})
	}
}

func TestParseWebAuthnAssertionAcceptsOmittedType(t *testing.T) {
	payload := webAuthnPayload()
	raw := webAuthnFixture("",
		b64urlRaw(clientData(b64urlRaw(payload[:]))),
		b64urlRaw(authenticatorData(flagUserPresent, 1)),
		b64urlRaw([]byte{9, 9, 9}))

	if _, err := ParseWebAuthnAssertionForPayload(raw, payload); err != nil {
		t.Fatalf("ParseWebAuthnAssertionForPayload with an omitted type: %v", err)
	}
}

func TestParseWebAuthnAssertionRejects(t *testing.T) {
	payload := webAuthnPayload()
	goodClientData := b64urlRaw(clientData(b64urlRaw(payload[:])))
	goodAuthData := b64urlRaw(authenticatorData(flagUserPresent, 1))
	goodSignature := b64urlRaw([]byte{1, 2, 3})

	tests := []struct {
		name     string
		raw      []byte
		sentinel error
	}{
		{
			name:     "empty input",
			raw:      nil,
			sentinel: ErrWebAuthnMalformedJSON,
		},
		{
			name:     "assertion is not JSON",
			raw:      []byte("{not json"),
			sentinel: ErrWebAuthnMalformedJSON,
		},
		{
			name: "clientDataJSON is not JSON",
			raw: webAuthnFixture("public-key",
				b64urlRaw([]byte("{not json")), goodAuthData, goodSignature),
			sentinel: ErrWebAuthnMalformedJSON,
		},
		{
			name: "missing clientDataJSON",
			raw:  webAuthnFixture("public-key", "", goodAuthData, goodSignature),
			// An absent clientDataJSON parses as an empty string, which the
			// field decoder reports as malformed rather than missing; both
			// are refusals, and the assertion below pins which one.
			sentinel: ErrWebAuthnMissingField,
		},
		{
			name:     "missing authenticatorData",
			raw:      webAuthnFixture("public-key", goodClientData, "", goodSignature),
			sentinel: ErrWebAuthnMissingField,
		},
		{
			name:     "missing signature",
			raw:      webAuthnFixture("public-key", goodClientData, goodAuthData, ""),
			sentinel: ErrWebAuthnMissingField,
		},
		{
			name: "missing challenge",
			raw: webAuthnFixture("public-key",
				b64urlRaw(clientData("")), goodAuthData, goodSignature),
			sentinel: ErrWebAuthnMissingField,
		},
		{
			name: "truncated authenticatorData",
			raw: webAuthnFixture("public-key", goodClientData,
				b64urlRaw(authenticatorData(flagUserPresent, 1)[:authDataMinLen-1]), goodSignature),
			sentinel: ErrWebAuthnTruncatedAuthenticatorData,
		},
		{
			name: "authenticatorData is not base64url",
			raw:  webAuthnFixture("public-key", goodClientData, "!!!!", goodSignature),
			// "!!!!" is not decodable in any base64 alphabet.
			sentinel: ErrWebAuthnMalformedField,
		},
		{
			name:     "signature is not base64url",
			raw:      webAuthnFixture("public-key", goodClientData, goodAuthData, "!!!!"),
			sentinel: ErrWebAuthnMalformedField,
		},
		{
			name: "challenge is not base64url or hex",
			raw: webAuthnFixture("public-key",
				b64urlRaw(clientData("not*a*challenge")), goodAuthData, goodSignature),
			sentinel: ErrWebAuthnMalformedField,
		},
		{
			name: "unexpected credential type",
			raw: webAuthnFixture("password",
				goodClientData, goodAuthData, goodSignature),
			sentinel: ErrWebAuthnMalformedField,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseWebAuthnAssertion(tt.raw)
			if err == nil {
				t.Fatal("ParseWebAuthnAssertion returned nil error, want a refusal")
			}
			if !errors.Is(err, tt.sentinel) {
				t.Errorf("errors.Is(%v, %v) = false, want true", err, tt.sentinel)
			}
		})
	}
}

// TestParseWebAuthnAssertionRejects is written so the "missing clientDataJSON"
// case cannot pass for the wrong reason: the fixture helper always emits the
// member, so that case is exercised by an explicit pre-built blob where the
// member is absent.
func TestParseWebAuthnAssertionMissingBase64Field(t *testing.T) {
	// clientDataJSON absent entirely (not merely empty), to prove the two
	// failure modes are told apart from a decode failure. The other fields
	// are valid, so the missing member is what the parser reports.
	raw := []byte(fmt.Sprintf(
		`{"id":"x","type":"public-key","response":{"authenticatorData":%q,"signature":%q}}`,
		b64urlRaw(authenticatorData(flagUserPresent, 1)), b64urlRaw([]byte{1, 2, 3})))

	_, err := ParseWebAuthnAssertion(raw)
	if !errors.Is(err, ErrWebAuthnMissingField) {
		t.Fatalf("errors.Is(%v, ErrWebAuthnMissingField) = false, want true", err)
	}
}

func TestParseWebAuthnAssertionChallengeMismatch(t *testing.T) {
	payload := webAuthnPayload()
	other := sha256.Sum256([]byte("a different payload"))

	raw := realAssertion(payload)

	// The parser itself succeeds: the challenge decodes, it is just the wrong
	// one.
	if _, err := ParseWebAuthnAssertion(raw); err != nil {
		t.Fatalf("ParseWebAuthnAssertion: %v", err)
	}

	_, err := ParseWebAuthnAssertionForPayload(raw, other)
	if !errors.Is(err, ErrWebAuthnChallengeMismatch) {
		t.Fatalf("errors.Is(%v, ErrWebAuthnChallengeMismatch) = false, want true", err)
	}

	assertion, err := ParseWebAuthnAssertion(raw)
	if err != nil {
		t.Fatalf("ParseWebAuthnAssertion: %v", err)
	}
	if err := assertion.VerifyChallenge(other[:]); !errors.Is(err, ErrWebAuthnChallengeMismatch) {
		t.Errorf("VerifyChallenge(wrong) = %v, want ErrWebAuthnChallengeMismatch", err)
	}
	if err := assertion.VerifyChallenge(payload[:]); err != nil {
		t.Errorf("VerifyChallenge(right) = %v, want nil", err)
	}
	if err := assertion.VerifyChallenge(nil); !errors.Is(err, ErrWebAuthnChallengeMismatch) {
		t.Errorf("VerifyChallenge(nil) = %v, want ErrWebAuthnChallengeMismatch", err)
	}
}

// TestVerifyChallengeOnNilAssertion proves the guard does not panic on a nil
// receiver, which a caller could reach by ignoring a parser error.
func TestVerifyChallengeOnNilAssertion(t *testing.T) {
	var assertion *WebAuthnAssertion
	if err := assertion.VerifyChallenge([]byte{1}); !errors.Is(err, ErrWebAuthnChallengeMismatch) {
		t.Errorf("nil.VerifyChallenge = %v, want ErrWebAuthnChallengeMismatch", err)
	}
	if got := assertion.Flags(); got != 0 {
		t.Errorf("nil.Flags() = 0x%02x, want 0", got)
	}
}
