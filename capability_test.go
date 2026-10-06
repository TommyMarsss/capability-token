package capability_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	cap "github.com/TommyMarsss/capability-token"
)

func testClock() (func() time.Time, *time.Time) {
	t0 := time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)
	cur := t0
	return func() time.Time { return cur }, &cur
}

func mustRoot(t *testing.T) (*cap.Authority, string) {
	t.Helper()
	clock, _ := testClock()
	a, root, err := cap.NewRoot("root",
		[]string{"doc:read", "doc:write", "doc:delete", "user:admin"},
		clock().Add(72*time.Hour), cap.WithClock(clock))
	if err != nil {
		t.Fatalf("NewRoot: %v", err)
	}
	return a, root
}

// ---------------------------------------------------------------------------
// Capability set basics
// ---------------------------------------------------------------------------

func TestCapabilitiesSubset(t *testing.T) {
	all := cap.NewCapabilities("b", "a", "a", " c ")
	if got := all.String(); got != "[a b c]" { // sorted, deduped, trimmed
		t.Fatalf("NewCapabilities canonicalization = %q, want [a b c]", got)
	}
	full := cap.NewCapabilities("a", "b", "c")
	if !cap.NewCapabilities("a", "c").IsSubsetOf(full) {
		t.Error("subset {a,c} not recognized")
	}
	if cap.NewCapabilities("a", "d").IsSubsetOf(full) {
		t.Error("{a,d} must not be a subset of {a,b,c}")
	}
	empty := cap.NewCapabilities()
	if !empty.IsSubsetOf(full) {
		t.Error("empty set must be a subset of every set")
	}
	if !empty.IsSubsetOf(empty) {
		t.Error("empty set must be a subset of itself")
	}
}

// ---------------------------------------------------------------------------
// Happy path: recursive signature-chain verification
// ---------------------------------------------------------------------------

func TestValidMultilevelChain(t *testing.T) {
	a, root := mustRoot(t)

	alice, err := a.Delegate(root, "alice",
		[]string{"doc:read", "doc:write"}, clock2(a).Add(48*time.Hour))
	if err != nil {
		t.Fatalf("delegate alice: %v", err)
	}
	bob, err := a.Delegate(alice, "bob",
		[]string{"doc:write"}, clock2(a).Add(24*time.Hour))
	if err != nil {
		t.Fatalf("delegate bob: %v", err)
	}
	carol, err := a.Delegate(bob, "carol",
		[]string{"doc:write"}, clock2(a).Add(12*time.Hour))
	if err != nil {
		t.Fatalf("delegate carol: %v", err)
	}

	for name, raw := range map[string]string{"root": root, "alice": alice, "bob": bob, "carol": carol} {
		claims, err := a.Verify(raw)
		if err != nil {
			t.Fatalf("Verify(%s): %v", name, err)
		}
		if claims.Issuer != name {
			t.Errorf("Verify(%s) issuer = %q", name, claims.Issuer)
		}
	}

	// Parent linkage is present in the claims.
	bobClaims, _ := a.Verify(bob)
	carolClaims, _ := a.Verify(carol)
	if carolClaims.ParentID != bobClaims.TokenID {
		t.Error("carol does not point at bob as parent")
	}
}

// clock2 returns a time offset from the fixed test clock by re-deriving the
// base; authorities in this file all use the same t0.
func clock2(_ *cap.Authority) time.Time {
	return time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)
}

// ---------------------------------------------------------------------------
// Requirement 1: privilege escalation must be refused
// ---------------------------------------------------------------------------

func TestDelegateRejectsCapabilityEscalation(t *testing.T) {
	a, root := mustRoot(t)
	alice, err := a.Delegate(root, "alice",
		[]string{"doc:read", "doc:write"}, clock2(a).Add(48*time.Hour))
	if err != nil {
		t.Fatalf("delegate alice: %v", err)
	}

	cases := []struct {
		name string
		caps []string
	}{
		{"add a parent capability", []string{"doc:read", "doc:delete"}},
		{"foreign namespace", []string{"user:admin"}},
		{"mixed known and unknown", []string{"doc:read", "doc:write", "user:admin"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := a.Delegate(alice, "mallory", tc.caps, clock2(a).Add(8*time.Hour))
			if !errors.Is(err, cap.ErrCapabilityEscalation) {
				t.Fatalf("Delegate(%v) err = %v, want ErrCapabilityEscalation", tc.caps, err)
			}
		})
	}
}

// A child may not request capabilities missing at the ROOT either.
func TestRootCapsAreTheCeiling(t *testing.T) {
	a, root := mustRoot(t)
	_, err := a.Delegate(root, "x", []string{"sys:kernel"}, clock2(a).Add(1*time.Hour))
	if !errors.Is(err, cap.ErrCapabilityEscalation) {
		t.Fatalf("err = %v, want ErrCapabilityEscalation", err)
	}
}

// ---------------------------------------------------------------------------
// Requirement 1: lifetime extension must be refused
// ---------------------------------------------------------------------------

func TestDelegateRejectsExpiryExtension(t *testing.T) {
	clock, cur := testClock()
	a, root, err := cap.NewRoot("root", []string{"doc:read"},
		cur.Add(24*time.Hour), cap.WithClock(clock))
	if err != nil {
		t.Fatalf("NewRoot: %v", err)
	}
	// alice expires at +12h.
	alice, err := a.Delegate(root, "alice", []string{"doc:read"}, cur.Add(12*time.Hour))
	if err != nil {
		t.Fatalf("delegate alice: %v", err)
	}

	// Child outliving its immediate parent.
	if _, err := a.Delegate(alice, "long1", []string{"doc:read"}, cur.Add(13*time.Hour)); !errors.Is(err, cap.ErrExpiryExtended) {
		t.Fatalf("+13h vs parent +12h: err = %v, want ErrExpiryExtended", err)
	}
	// Child within its parent's life but past the grandparent's.
	bob, err := a.Delegate(alice, "bob", []string{"doc:read"}, cur.Add(10*time.Hour))
	if err != nil {
		t.Fatalf("delegate bob: %v", err)
	}
	if _, err := a.Delegate(bob, "long2", []string{"doc:read"}, cur.Add(20*time.Hour)); !errors.Is(err, cap.ErrExpiryExtended) {
		t.Fatalf("+20h vs grandparent +24h but parent +10h: err = %v, want ErrExpiryExtended", err)
	}
	// Past expiry is rejected too.
	if _, err := a.Delegate(alice, "past", []string{"doc:read"}, cur.Add(-1*time.Hour)); err == nil {
		t.Fatal("delegation expiring in the past must be rejected")
	}
}

// Equal bounds are legal: subset includes equality, exp <= parent exp.
func TestDelegateAllowsEqualBounds(t *testing.T) {
	a, root := mustRoot(t)
	base := clock2(a)
	alice, err := a.Delegate(root, "alice",
		[]string{"doc:read", "doc:write"}, base.Add(48*time.Hour))
	if err != nil {
		t.Fatalf("delegate alice: %v", err)
	}
	bob, err := a.Delegate(alice, "bob",
		[]string{"doc:read", "doc:write"}, base.Add(48*time.Hour)) // identical caps and exp
	if err != nil {
		t.Fatalf("equal caps/exp should be allowed: %v", err)
	}
	if _, err := a.Verify(bob); err != nil {
		t.Fatalf("bob should verify: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Requirement 2: revocation propagation
// ---------------------------------------------------------------------------

// buildRevocationFixture creates:
//
//	root
//	├─ alice
//	│  ├─ bob
//	│  │  ├─ carol
//	│  │  │  └─ dave
//	│  │  └─ erin
//	│  └─ frank
//	└─ grace (independent branch)
//	   └─ heidi
func buildRevocationFixture(t *testing.T) (*cap.Authority, map[string]string) {
	t.Helper()
	a, root := mustRoot(t)
	base := clock2(a)
	toks := map[string]string{"root": root}
	issue := func(name, parent string, exp time.Duration, caps ...string) {
		t.Helper()
		raw, err := a.Delegate(toks[parent], name, caps, base.Add(exp))
		if err != nil {
			t.Fatalf("delegate %s: %v", name, err)
		}
		toks[name] = raw
	}
	issue("alice", "root", 48*time.Hour, "doc:read", "doc:write")
	issue("bob", "alice", 36*time.Hour, "doc:read", "doc:write")
	issue("carol", "bob", 24*time.Hour, "doc:read")
	issue("dave", "carol", 12*time.Hour, "doc:read")
	issue("erin", "bob", 24*time.Hour, "doc:write")
	issue("frank", "alice", 24*time.Hour, "doc:read")
	issue("grace", "root", 48*time.Hour, "user:admin")
	issue("heidi", "grace", 24*time.Hour, "user:admin")
	return a, toks
}

func TestRevocationPropagatesDownOnly(t *testing.T) {
	a, toks := buildRevocationFixture(t)

	if err := a.Revoke(toks["bob"]); err != nil {
		t.Fatalf("revoke bob: %v", err)
	}

	dead := []string{"bob", "carol", "dave", "erin"}
	for _, name := range dead {
		if _, err := a.Verify(toks[name]); !errors.Is(err, cap.ErrTokenRevoked) {
			t.Errorf("Verify(%s) err = %v, want ErrTokenRevoked", name, err)
		}
	}

	// Ancestors and the sibling branch, including a sibling of bob, stay valid.
	alive := []string{"root", "alice", "frank", "grace", "heidi"}
	for _, name := range alive {
		if _, err := a.Verify(toks[name]); err != nil {
			t.Errorf("Verify(%s) err = %v, want nil (unaffected branch)", name, err)
		}
	}
}

func TestRevocationIsImmediate(t *testing.T) {
	a, toks := buildRevocationFixture(t)
	if _, err := a.Verify(toks["dave"]); err != nil {
		t.Fatalf("dave valid before revocation: %v", err)
	}
	if err := a.Revoke(toks["carol"]); err != nil {
		t.Fatal(err)
	}
	// No grace period, no clock movement: invalid immediately.
	if _, err := a.Verify(toks["dave"]); !errors.Is(err, cap.ErrTokenRevoked) {
		t.Fatalf("dave err = %v, want ErrTokenRevoked", err)
	}
}

func TestRevokeRootKillsEverything(t *testing.T) {
	a, toks := buildRevocationFixture(t)
	if err := a.Revoke(a.RootToken()); err != nil { // accept raw token, not just id
		t.Fatal(err)
	}
	for name, raw := range toks {
		if _, err := a.Verify(raw); !errors.Is(err, cap.ErrTokenRevoked) {
			t.Errorf("Verify(%s) err = %v, want ErrTokenRevoked after root revocation", name, err)
		}
	}
}

func TestRevokedTokenCannotDelegate(t *testing.T) {
	a, toks := buildRevocationFixture(t)
	if err := a.Revoke(toks["bob"]); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Delegate(toks["bob"], "eve", []string{"doc:read"}, clock2(a).Add(1*time.Hour)); !errors.Is(err, cap.ErrTokenRevoked) {
		t.Fatalf("Delegate from revoked token err = %v, want ErrTokenRevoked", err)
	}
	// Unknown token id cannot be revoked.
	if err := a.Revoke("not-an-id"); !errors.Is(err, cap.ErrUnknownToken) {
		t.Fatalf("revoke unknown err = %v, want ErrUnknownToken", err)
	}
}

// Snapshot classification: revoked source vs blocked descendants.
func TestSnapshotClassification(t *testing.T) {
	a, toks := buildRevocationFixture(t)
	if err := a.Revoke(toks["bob"]); err != nil {
		t.Fatal(err)
	}
	snap := a.Snapshot()
	status := map[string]cap.NodeStatus{}
	for _, n := range snap.Nodes {
		_, verifyErr := a.Verify(n.Raw)
		status[n.ShortID] = n.Status
		// Snapshot validity agrees with Verify.
		switch n.Status {
		case cap.StatusValid:
			if verifyErr != nil {
				t.Errorf("%s snapshot valid but Verify: %v", n.ShortID, verifyErr)
			}
		case cap.StatusRevoked, cap.StatusAncestorRevoked:
			if !errors.Is(verifyErr, cap.ErrTokenRevoked) {
				t.Errorf("%s status=%s but Verify err = %v", n.ShortID, n.Status, verifyErr)
			}
		}
	}
	want := map[string]cap.NodeStatus{
		"bob": cap.StatusRevoked, "carol": cap.StatusAncestorRevoked,
		"dave": cap.StatusAncestorRevoked, "erin": cap.StatusAncestorRevoked,
		"alice": cap.StatusValid, "frank": cap.StatusValid,
		"grace": cap.StatusValid, "heidi": cap.StatusValid,
	}
	idOf := func(name string) string {
		p, err := cap.Parse(toks[name])
		if err != nil {
			t.Fatal(err)
		}
		return p.Claims.TokenID[:12]
	}
	for name, st := range want {
		if got := status[idOf(name)]; got != st {
			t.Errorf("%s snapshot status = %q, want %q", name, got, st)
		}
	}
}

// ---------------------------------------------------------------------------
// Requirement 1/3: expiry evaluation
// ---------------------------------------------------------------------------

func TestExpiry(t *testing.T) {
	clock, cur := testClock()
	a, root, err := cap.NewRoot("root", []string{"doc:read"},
		cur.Add(24*time.Hour), cap.WithClock(clock))
	if err != nil {
		t.Fatal(err)
	}
	alice, err := a.Delegate(root, "alice", []string{"doc:read"}, cur.Add(6*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Verify(alice); err != nil {
		t.Fatalf("alice valid now: %v", err)
	}
	*cur = cur.Add(6 * time.Hour) // exactly at expiry
	if _, err := a.Verify(alice); !errors.Is(err, cap.ErrTokenExpired) {
		t.Fatalf("at expiry err = %v, want ErrTokenExpired", err)
	}
	if _, err := a.Verify(root); err != nil {
		t.Fatalf("root still valid: %v", err)
	}
	*cur = cur.Add(24 * time.Hour) // root expired as well
	if _, err := a.Verify(root); !errors.Is(err, cap.ErrTokenExpired) {
		t.Fatalf("root err = %v, want ErrTokenExpired", err)
	}
}

// ---------------------------------------------------------------------------
// Requirement 3 (tests): tampered tokens fail verification
// ---------------------------------------------------------------------------

// tamperPayload decodes the payload, mutates the JSON, re-encodes it, and
// keeps the original signature — a classic forgery attempt.
func tamperPayload(t *testing.T, raw string, mutate func(map[string]any)) string {
	t.Helper()
	parts := strings.Split(raw, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		t.Fatal(err)
	}
	mutate(m)
	nb, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	parts[1] = base64.RawURLEncoding.EncodeToString(nb)
	return strings.Join(parts, ".")
}

func TestTamperedPayloadRejected(t *testing.T) {
	a, toks := buildRevocationFixture(t)

	// Add a capability the parent never granted.
	forged := tamperPayload(t, toks["dave"], func(m map[string]any) {
		m["caps"] = []any{"doc:read", "doc:delete"}
	})
	if _, err := a.Verify(forged); !errors.Is(err, cap.ErrBadSignature) {
		t.Fatalf("payload tamper err = %v, want ErrBadSignature", err)
	}

	// Repoint the parent (attempt to escape the revoked subtree).
	reparented := tamperPayload(t, toks["dave"], func(m map[string]any) {
		rootClaims, _ := a.Verify(toks["root"])
		m["pid"] = rootClaims.TokenID
	})
	if _, err := a.Verify(reparented); !errors.Is(err, cap.ErrBadSignature) {
		t.Fatalf("parent tamper err = %v, want ErrBadSignature", err)
	}
}

func TestTamperedSignatureOrHeaderRejected(t *testing.T) {
	a, toks := buildRevocationFixture(t)

	flip := func(raw string, seg int) string {
		parts := strings.Split(raw, ".")
		b, _ := base64.RawURLEncoding.DecodeString(parts[seg])
		b[0] ^= 0xff
		parts[seg] = base64.RawURLEncoding.EncodeToString(b)
		return strings.Join(parts, ".")
	}

	for name, raw := range map[string]string{
		"flipped signature": flip(toks["dave"], 2),
		"flipped header":    flip(toks["dave"], 0),
	} {
		if _, err := a.Verify(raw); err == nil {
			t.Fatalf("%s: Verify unexpectedly succeeded", name)
		}
	}

	for _, bad := range []string{"", "a.b", "a.b.c.d", "...", "###.###.###"} {
		if _, err := a.Verify(bad); !errors.Is(err, cap.ErrMalformedToken) {
			t.Fatalf("Verify(%q) err = %v, want ErrMalformedToken", bad, err)
		}
	}

	// Appending a byte changes the presented serialization so it no longer
	// matches the authoritative stored copy.
	if _, err := a.Verify(toks["dave"] + "x"); err == nil {
		t.Fatalf("modified token string must not verify")
	} else if !errors.Is(err, cap.ErrBadSignature) && !errors.Is(err, cap.ErrMalformedToken) {
		t.Fatalf("modified token err = %v, want ErrBadSignature/ErrMalformedToken", err)
	}
}
