package capability

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Algorithm identifies the signature algorithm used by a token.
const Algorithm = "EdDSA"

// Errors returned during token parsing and verification.
var (
	ErrMalformedToken    = errors.New("capability: malformed token")
	ErrBadAlgorithm      = errors.New("capability: unsupported signature algorithm")
	ErrBadSignature      = errors.New("capability: invalid signature")
	ErrRootNotSelf       = errors.New("capability: root token must be self-signed")
	ErrNoParent          = errors.New("capability: non-root token must reference a parent")
	ErrParentKeyMismatch = errors.New("capability: signature does not verify under the parent verification key")
)

// Claims is the signed payload of a capability token.
type Claims struct {
	// TokenID is the unique, immutable identifier of the token.
	TokenID string `json:"tid"`
	// ParentID is the TokenID of the delegating parent; empty for the root.
	ParentID string `json:"pid,omitempty"`
	// Issuer is a human-readable name for the subject holding the token.
	Issuer string `json:"iss"`
	// Caps are the capabilities delegated to this token.
	Caps Capabilities `json:"caps"`
	// Iat is the issuance time as a Unix timestamp (seconds).
	Iat int64 `json:"iat"`
	// Exp is the expiry time as a Unix timestamp (seconds).
	Exp int64 `json:"exp"`
}

// Expired reports whether the token's expiry is at or before t.
func (c Claims) Expired(t time.Time) bool {
	return !t.Before(time.Unix(c.Exp, 0)) // t >= exp
}

// Header is the signed header of a capability token.
type Header struct {
	Alg string `json:"alg"`
	// Kid is the Base64-RawURLEncoding of the ed25519 public key that signed
	// this token. It is also the token's identity for key lookup.
	Kid string `json:"kid"`
}

// Key is an ed25519 key pair used to sign (delegated) tokens.
type Key struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// GenerateKey creates a fresh ed25519 key pair.
func GenerateKey() (Key, error) {
	return GenerateKeyFrom(rand.Reader)
}

// GenerateKeyFrom creates a key pair from the provided entropy source; it
// exists mainly to make tests deterministic.
func GenerateKeyFrom(r io.Reader) (Key, error) {
	pub, priv, err := ed25519.GenerateKey(r)
	if err != nil {
		return Key{}, err
	}
	return Key{Public: pub, Private: priv}, nil
}

// KeyID returns the canonical key identifier: Base64-RawURL of the public key.
func KeyID(pub ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(pub)
}

// encodePart serializes a value with the compact, stable JSON form used for
// signing.
func encodePart(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Sign produces a compact token string of the form header.payload.signature.
//
// The signature covers the exact bytes "header.payload" (each part Base64
// RawURL encoded), so any tampering with either part is detectable.
func Sign(h Header, c Claims, signer ed25519.PrivateKey) (string, error) {
	if h.Alg != Algorithm {
		return "", ErrBadAlgorithm
	}
	hp, err := encodePart(h)
	if err != nil {
		return "", err
	}
	pp, err := encodePart(c)
	if err != nil {
		return "", err
	}
	signingInput := hp + "." + pp
	sig := ed25519.Sign(signer, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// ParsedToken is the decoded content of a token string.
type ParsedToken struct {
	Raw          string
	Header       Header
	Claims       Claims
	Signature    []byte
	SigningInput string
}

// Parse decodes a token string without verifying it.
func Parse(raw string) (ParsedToken, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return ParsedToken{}, ErrMalformedToken
	}
	var h Header
	if err := decodePart(parts[0], &h); err != nil {
		return ParsedToken{}, fmt.Errorf("%w: bad header: %v", ErrMalformedToken, err)
	}
	if h.Alg != Algorithm {
		return ParsedToken{}, ErrBadAlgorithm
	}
	var c Claims
	if err := decodePart(parts[1], &c); err != nil {
		return ParsedToken{}, fmt.Errorf("%w: bad payload: %v", ErrMalformedToken, err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return ParsedToken{}, fmt.Errorf("%w: bad signature encoding: %v", ErrMalformedToken, err)
	}
	return ParsedToken{
		Raw:          raw,
		Header:       h,
		Claims:       c,
		Signature:    sig,
		SigningInput: parts[0] + "." + parts[1],
	}, nil
}

func decodePart(part string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// verifySignature checks the signature against a public key.
func (p ParsedToken) verifySignature(pub ed25519.PublicKey) bool {
	return ed25519.Verify(pub, []byte(p.SigningInput), p.Signature)
}

// VerifySignature checks the token signature against pub directly, without
// consulting an authority. It is the cryptographic primitive the chain
// validation is built on.
func (p ParsedToken) VerifySignature(pub ed25519.PublicKey) bool {
	return p.verifySignature(pub)
}
