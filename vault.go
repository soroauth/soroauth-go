package soroauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// Defaults for a Vault transit signer. The mount name is Vault's conventional
// path for the transit secrets engine; override it when the engine is mounted
// elsewhere.
const (
	defaultVaultMount       = "transit"
	defaultVaultHTTPTimeout = 10 * time.Second
	maxVaultResponseBytes   = 1 << 20
)

// VaultConfig configures a VaultSigner.
//
// BaseURL is the Vault server, for example "https://vault.internal:8200". The
// transit engine is mounted at Mount (default "transit") and the signing key is
// named KeyName. Address is the G… account the key signs for; NewVaultSigner
// refuses a key whose public key derives a different address.
type VaultConfig struct {
	// BaseURL is the Vault server's origin, without a trailing slash. Required.
	BaseURL string

	// Token is sent as X-Vault-Token on every request. Required.
	//
	// This library does not renew tokens. Renewal belongs in a Vault Agent or
	// an explicit token helper; an expired or revoked token surfaces here as
	// ErrVaultUnauthorized rather than as a retry loop.
	Token string

	// Mount is the transit secrets engine's mount path. Empty means "transit".
	Mount string

	// KeyName is the transit key to sign with. Required. The key must be an
	// ed25519 key; any other type is refused with ErrVaultKeyType.
	KeyName string

	// Address is the G… account the key signs for. Required.
	Address string

	// HTTPClient is used for every request. Empty means a client with a
	// 10-second timeout.
	HTTPClient *http.Client
}

// VaultSigner is a Signer backed by Vault's transit engine: the ed25519 private
// key lives in Vault and never reaches this process.
//
// It produces the built-in classic-account signature shape — a vector holding
// one {public_key, signature} map, the same shape NewEd25519Signer produces —
// because a Vault transit ed25519 key is an ordinary Stellar signing key.
//
// The public key is read once, at construction, from
// GET /v1/:mount/keys/:name. Vault returns an ed25519 public key as the base64
// encoding of the raw 32-byte key in the response's "keys" map (hashicorp/vault
// issue #25141). That key derives the account address, which must equal the
// configured one; otherwise construction fails with ErrSignerAddressMismatch.
//
// Signing is POST /v1/:mount/sign/:name with the 32-byte payload base64-encoded
// in "input". No hash_algorithm is sent: Vault documents that ed25519 "specifies
// its own hash algorithm", so the input is signed as-is, which is what a Stellar
// account requires — the payload is already SHA-256(HashIdPreimage) and ed25519
// must sign those 32 bytes directly, not a further hash of them.
//
// Every signature is verified against the public key before it is returned; a
// mismatch is ErrSignatureMismatch.
//
// The minimum Vault policy the signer needs, and nothing more:
//
//	path "transit/keys/<name>" {
//	  capabilities = ["read"]
//	}
//	path "transit/sign/<name>" {
//	  capabilities = ["update"]
//	}
//
// "update" is what Vault requires for POST to /transit/sign/:name, even though
// the operation creates no data. The key needs no "create", no
// "delete", and no "export": an exportable key would let the private key leave
// Vault, which defeats the reason to use transit at all.
type VaultSigner struct {
	baseURL   *url.URL
	token     string
	mount     string
	keyName   string
	address   string
	client    *http.Client
	publicKey ed25519.PublicKey
	rawKey    []byte
}

// NewVaultSigner validates cfg, reads the signing key's public key from Vault,
// and returns a Signer that signs through the transit engine.
//
// It performs one network round trip, so it takes a context. A failure to
// authenticate surfaces as ErrVaultUnauthorized, a missing key as
// ErrVaultKeyNotFound, and a key of the wrong type as ErrVaultKeyType.
func NewVaultSigner(ctx context.Context, cfg VaultConfig) (*VaultSigner, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("soroauth: new vault signer: base URL is required")
	}
	baseURL, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("soroauth: new vault signer: parsing base URL: %w", err)
	}
	if baseURL.Scheme == "" || baseURL.Host == "" {
		return nil, fmt.Errorf("soroauth: new vault signer: base URL %q must be absolute", cfg.BaseURL)
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("soroauth: new vault signer: token is required: %w", ErrVaultUnauthorized)
	}
	if cfg.KeyName == "" {
		return nil, fmt.Errorf("soroauth: new vault signer: key name is required")
	}
	if _, err := rawEd25519Key(cfg.Address); err != nil {
		return nil, fmt.Errorf("soroauth: new vault signer: %w", err)
	}

	mount := cfg.Mount
	if mount == "" {
		mount = defaultVaultMount
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultVaultHTTPTimeout}
	}

	s := &VaultSigner{
		baseURL: baseURL,
		token:   cfg.Token,
		mount:   mount,
		keyName: cfg.KeyName,
		address: cfg.Address,
		client:  client,
	}

	publicKey, raw, err := s.readPublicKey(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.checkAddress(raw); err != nil {
		return nil, err
	}
	s.publicKey = publicKey
	s.rawKey = raw
	return s, nil
}

// Address returns the G… account this signer signs for.
//
// The public key is fixed for the life of the signer. Rotating the transit key
// changes the account, so a caller that rotates builds a new signer.
func (s *VaultSigner) Address() string { return s.address }

func (s *VaultSigner) checkAddress(raw []byte) error {
	derived, err := strkey.Encode(strkey.VersionByteAccountID, raw)
	if err != nil {
		return fmt.Errorf("soroauth: vault signer: encoding the public key's address: %w", err)
	}
	if derived != s.address {
		return fmt.Errorf("soroauth: vault signer: transit key %q derives %s, configured address is %s: %w",
			s.keyName, derived, s.address, ErrSignerAddressMismatch)
	}
	return nil
}

// readPublicKey fetches the transit key and returns its public key as a parsed
// ed25519 key and as the raw 32 bytes.
func (s *VaultSigner) readPublicKey(ctx context.Context) (ed25519.PublicKey, []byte, error) {
	body, err := s.do(ctx, http.MethodGet, "/v1/"+s.mount+"/keys/"+s.keyName, nil, ErrVaultKeyNotFound)
	if err != nil {
		return nil, nil, err
	}

	var response struct {
		Data struct {
			Type          string         `json:"type"`
			LatestVersion int            `json:"latest_version"`
			Keys          map[string]any `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, nil, fmt.Errorf("soroauth: vault signer: decoding the key response: %w", err)
	}
	if response.Data.Type != "ed25519" {
		return nil, nil, fmt.Errorf("soroauth: vault signer: key %q is %q, need ed25519: %w",
			s.keyName, response.Data.Type, ErrVaultKeyType)
	}

	raw, err := latestPublicKey(response.Data.Keys, response.Data.LatestVersion)
	if err != nil {
		return nil, nil, fmt.Errorf("soroauth: vault signer: key %q: %w", s.keyName, err)
	}
	return ed25519.PublicKey(raw), raw, nil
}

// latestPublicKey picks the newest version out of a Vault key's "keys" map and
// returns its raw bytes. Vault encodes an ed25519 public key as the base64 of
// the raw 32 bytes (hashicorp/vault issue #25141).
func latestPublicKey(keys map[string]any, latestVersion int) ([]byte, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("the key has no versions")
	}

	versions := make([]int, 0, len(keys))
	for name := range keys {
		version, err := strconv.Atoi(name)
		if err != nil {
			return nil, fmt.Errorf("unexpected version name %q", name)
		}
		versions = append(versions, version)
	}
	sort.Ints(versions)

	version := versions[len(versions)-1]
	if latestVersion > 0 {
		version = latestVersion
	}
	value, ok := keys[strconv.Itoa(version)]
	if !ok {
		return nil, fmt.Errorf("version %d is missing from the key ring", version)
	}
	encoded, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("version %d is not a base64 public key", version)
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("version %d is not valid base64: %w", version, err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("version %d decodes to %d bytes, an ed25519 public key is %d",
			version, len(raw), ed25519.PublicKeySize)
	}
	return raw, nil
}

// Sign builds the preimage's payload hash, has it signed by Vault, verifies the
// signature, and returns the classic-account signature shape.
func (s *VaultSigner) Sign(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
	if err := ctx.Err(); err != nil {
		return xdr.ScVal{}, fmt.Errorf("soroauth: vault sign: %w", err)
	}
	if s.publicKey == nil {
		return xdr.ScVal{}, fmt.Errorf("soroauth: vault sign: %w", ErrMissingSigner)
	}

	// The signer is handed both the preimage and its digest. Re-deriving the
	// digest and comparing is cheap, and it is the check that stops a caller
	// from signing a payload that does not belong to the preimage it approved.
	expected, err := Payload(preimage)
	if err != nil {
		return xdr.ScVal{}, fmt.Errorf("soroauth: vault sign: %w", err)
	}
	if !bytes.Equal(expected[:], payload[:]) {
		return xdr.ScVal{}, fmt.Errorf("soroauth: vault sign: payload does not match the preimage: %w", ErrSignatureMismatch)
	}

	request := map[string]string{"input": base64.StdEncoding.EncodeToString(payload[:])}
	body, err := s.do(ctx, http.MethodPost, "/v1/"+s.mount+"/sign/"+s.keyName, request, ErrVaultKeyNotFound)
	if err != nil {
		return xdr.ScVal{}, fmt.Errorf("soroauth: vault sign: %w", err)
	}

	var response struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return xdr.ScVal{}, fmt.Errorf("soroauth: vault sign: decoding the sign response: %w", err)
	}
	signature, err := decodeVaultSignature(response.Data.Signature)
	if err != nil {
		return xdr.ScVal{}, fmt.Errorf("soroauth: vault sign: %w", err)
	}
	if !ed25519.Verify(s.publicKey, payload[:], signature) {
		return xdr.ScVal{}, fmt.Errorf("soroauth: vault sign: %w", ErrSignatureMismatch)
	}

	return scVec(accountSignature(s.rawKey, signature)), nil
}

// decodeVaultSignature strips Vault's "vault:v1:" prefix and base64-decodes the
// remainder, returning an error rather than silently signing with garbage.
func decodeVaultSignature(encoded string) ([]byte, error) {
	index := strings.LastIndex(encoded, ":")
	if index < 0 {
		return nil, fmt.Errorf("signature %q has no vault:vN: prefix", encoded)
	}
	signature, err := base64.StdEncoding.DecodeString(encoded[index+1:])
	if err != nil {
		return nil, fmt.Errorf("signature is not valid base64: %w", err)
	}
	return signature, nil
}

// do performs one request and returns the response body, mapping the status
// codes that call for a named error.
func (s *VaultSigner) do(ctx context.Context, method, path string, requestBody any, notFound error) ([]byte, error) {
	var body io.Reader
	if requestBody != nil {
		encoded, err := json.Marshal(requestBody)
		if err != nil {
			return nil, fmt.Errorf("encoding the request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}

	endpoint := *s.baseURL
	endpoint.Path = strings.TrimSuffix(endpoint.Path, "/") + path
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return nil, fmt.Errorf("building the request: %w", err)
	}
	request.Header.Set("X-Vault-Token", s.token)
	if requestBody != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	response, err := s.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("calling vault: %w", err)
	}
	defer response.Body.Close()

	limited := io.LimitReader(response.Body, maxVaultResponseBytes)
	responseBody, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("reading the response: %w", err)
	}

	switch {
	case response.StatusCode >= 200 && response.StatusCode < 300:
		return responseBody, nil
	case response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusUnauthorized:
		return nil, fmt.Errorf("%s %s: HTTP %d: %w", method, path, response.StatusCode, ErrVaultUnauthorized)
	case response.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("%s %s: HTTP %d: %w", method, path, response.StatusCode, notFound)
	default:
		return nil, fmt.Errorf("%s %s: HTTP %d: %s", method, path, response.StatusCode, strings.TrimSpace(string(responseBody)))
	}
}
