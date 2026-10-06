package capability_test

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	cap "github.com/TommyMarsss/capability-token"
)

// Cryptographic round-trip: a token verifies only under the exact key that
// signed it. This proves the rejection of forged tokens is genuine Ed25519
// verification, not just registry bookkeeping.
func TestSignParseVerifySignature(t *testing.T) {
	signer, err := cap.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	other, err := cap.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims := cap.Claims{
		TokenID: cap.KeyID(signer.Public),
		Issuer:  "root",
		Caps:    cap.NewCapabilities("doc:read"),
		Iat:     now.Unix(),
		Exp:     now.Add(time.Hour).Unix(),
	}
	raw, err := cap.Sign(cap.Header{Alg: cap.Algorithm, Kid: cap.KeyID(signer.Public)}, claims, signer.Private)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := cap.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.VerifySignature(signer.Public) {
		t.Fatal("signature must verify under the signing public key")
	}
	if parsed.VerifySignature(other.Public) {
		t.Fatal("signature must NOT verify under a different public key")
	}

	// Flip one signature byte: parsing still succeeds, crypto fails.
	parts := strings.Split(raw, ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	sig[len(sig)-1] ^= 0xff
	parts[2] = base64.RawURLEncoding.EncodeToString(sig)
	tampered := strings.Join(parts, ".")
	pt, err := cap.Parse(tampered)
	if err != nil {
		t.Fatalf("tampered token should still parse: %v", err)
	}
	if pt.VerifySignature(signer.Public) {
		t.Fatal("tampered signature must fail Ed25519 verification")
	}
}

func TestParseRejectsBadShapes(t *testing.T) {
	for _, raw := range []string{"", "x", "x.y", "x.y.z.w"} {
		if _, err := cap.Parse(raw); err == nil {
			t.Errorf("Parse(%q) unexpectedly succeeded", raw)
		}
	}
}
