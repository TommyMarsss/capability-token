package capability

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Delegation/validation errors. They are wrapped, never returned bare with
// extra context; callers can use errors.Is.
var (
	// ErrCapabilityEscalation is returned when a child requests a capability
	// its parent does not hold.
	ErrCapabilityEscalation = errors.New("capability: child capabilities must be a subset of the parent's")
	// ErrExpiryExtended is returned when a child's expiry is later than its
	// parent's.
	ErrExpiryExtended = errors.New("capability: child expiry must not exceed parent expiry")
	// ErrUnknownToken is returned when a token is not registered with the authority.
	ErrUnknownToken = errors.New("capability: unknown token")
	// ErrTokenRevoked is returned when a token or one of its ancestors is revoked.
	ErrTokenRevoked = errors.New("capability: token revoked")
	// ErrTokenExpired is returned when a token or one of its ancestors is expired.
	ErrTokenExpired = errors.New("capability: token expired")
	// ErrChainBroken is returned when a token references a parent that is not
	// its registered parent.
	ErrChainBroken = errors.New("capability: delegation chain is broken")
	// ErrInvalidDelegation is returned for malformed issuance parameters.
	ErrInvalidDelegation = errors.New("capability: invalid delegation request")
)

// record is the authority's stored state for one issued token.
type record struct {
	claims    Claims
	raw       string
	key       Key
	revoked   bool
	revokedAt int64
}

// Authority is an in-memory root issuer, delegation registry and revocation
// authority. It also acts as key custodian for every issued token, which keeps
// the demo self-contained; in a real deployment each token holder would keep
// their own private key and only expose the public part here.
//
// All methods are safe for concurrent use.
type Authority struct {
	mu      sync.RWMutex
	records map[string]*record // keyed by Claims.TokenID
	rootID  string
	now     func() time.Time
}

// Option configures an Authority at creation.
type Option func(*Authority)

// WithClock overrides the authority's clock (useful in tests).
func WithClock(now func() time.Time) Option {
	return func(a *Authority) { a.now = now }
}

// NewRoot creates an authority together with its self-signed root token.
//
// The root carries the full initial capability set and the given expiry.
func NewRoot(issuer string, caps []string, exp time.Time, opts ...Option) (*Authority, string, error) {
	if issuer == "" {
		return nil, "", fmt.Errorf("%w: empty root issuer", ErrInvalidDelegation)
	}
	rootCaps := NewCapabilities(caps...)
	if len(rootCaps) == 0 {
		return nil, "", fmt.Errorf("%w: root must carry at least one capability", ErrInvalidDelegation)
	}
	a := &Authority{
		records: make(map[string]*record),
		now:     time.Now,
	}
	for _, opt := range opts {
		opt(a)
	}
	now := a.now().Unix()
	if !exp.After(a.now()) {
		return nil, "", fmt.Errorf("%w: root expiry must be in the future", ErrInvalidDelegation)
	}

	key, err := GenerateKey()
	if err != nil {
		return nil, "", err
	}
	id := KeyID(key.Public)
	claims := Claims{
		TokenID: id,
		Issuer:  issuer,
		Caps:    rootCaps,
		Iat:     now,
		Exp:     exp.Unix(),
	}
	// The root is self-signed: its header kid is its own key id.
	raw, err := Sign(Header{Alg: Algorithm, Kid: id}, claims, key.Private)
	if err != nil {
		return nil, "", err
	}
	a.records[id] = &record{claims: claims, raw: raw, key: key}
	a.rootID = id
	return a, raw, nil
}

// RootToken returns the serialized root token.
func (a *Authority) RootToken() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.records[a.rootID].raw
}

// Delegate creates a child token from parentRaw. The child is signed with the
// parent's private key and may only carry a subset of the parent's
// capabilities and an expiry no later than the parent's.
func (a *Authority) Delegate(parentRaw, issuer string, caps []string, exp time.Time) (string, error) {
	if issuer == "" {
		return "", fmt.Errorf("%w: empty issuer", ErrInvalidDelegation)
	}
	childCaps := NewCapabilities(caps...)
	if len(childCaps) == 0 {
		return "", fmt.Errorf("%w: child must carry at least one capability", ErrInvalidDelegation)
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	parent, err := a.parseAndLookup(parentRaw)
	if err != nil {
		return "", err
	}
	now := a.now()
	if parent.revoked {
		return "", fmt.Errorf("%w: cannot delegate from revoked token %s", ErrTokenRevoked, shortID(parent.claims.TokenID))
	}
	if parent.claims.Expired(now) {
		return "", fmt.Errorf("%w: cannot delegate from expired token %s", ErrTokenExpired, shortID(parent.claims.TokenID))
	}

	// --- Monotonic delegation invariants -----------------------------------
	// 1. Capabilities can only shrink (subset).
	if !childCaps.IsSubsetOf(parent.claims.Caps) {
		return "", fmt.Errorf("%w: %s not contained in parent %s",
			ErrCapabilityEscalation, childCaps, parent.claims.Caps)
	}
	// 2. Lifetime can only shrink (exp <= parent exp).
	if exp.Unix() > parent.claims.Exp {
		return "", fmt.Errorf("%w: child exp %d > parent exp %d",
			ErrExpiryExtended, exp.Unix(), parent.claims.Exp)
	}
	if !exp.After(now) {
		return "", fmt.Errorf("%w: expiry must be in the future", ErrInvalidDelegation)
	}

	childKey, err := GenerateKey()
	if err != nil {
		return "", err
	}
	childID := KeyID(childKey.Public)
	if _, exists := a.records[childID]; exists { // astronomically unlikely, but checked
		return "", fmt.Errorf("capability: generated duplicate token id")
	}
	claims := Claims{
		TokenID:  childID,
		ParentID: parent.claims.TokenID,
		Issuer:   issuer,
		Caps:     childCaps,
		Iat:      now.Unix(),
		Exp:      exp.Unix(),
	}
	// The header kid identifies the SIGNING key: the parent's public key.
	raw, err := Sign(
		Header{Alg: Algorithm, Kid: parent.claims.TokenID},
		claims,
		parent.key.Private,
	)
	if err != nil {
		return "", err
	}
	a.records[childID] = &record{claims: claims, raw: raw, key: childKey}
	return raw, nil
}

// Revoke marks the token (identified by its raw serialization or its id) as
// revoked. Validity of its entire descendant subtree is derived lazily on
// every verification, so propagation is immediate.
func (a *Authority) Revoke(tokenRawOrID string) error {
	id := tokenRawOrID
	if looksLikeToken(tokenRawOrID) {
		p, err := Parse(tokenRawOrID)
		if err != nil {
			return err
		}
		id = p.Claims.TokenID
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	rec, ok := a.records[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownToken, shortID(id))
	}
	if !rec.revoked {
		rec.revoked = true
		rec.revokedAt = a.now().Unix()
	}
	return nil
}

// IsRevoked reports whether id itself is revoked (not counting ancestors).
func (a *Authority) IsRevoked(id string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	rec, ok := a.records[id]
	return ok && rec.revoked
}

// Verify validates raw at the current time and returns its claims on success.
// It verifies the complete delegation chain: every signature up to the
// self-signed root, every subset/expiry constraint, expiry, and the
// revocation status of the token and every ancestor.
func (a *Authority) Verify(raw string) (Claims, error) {
	return a.VerifyAt(raw, a.now())
}

// VerifyAt is Verify with an explicit evaluation time.
func (a *Authority) VerifyAt(raw string, at time.Time) (Claims, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	p, err := a.parseAndLookup(raw)
	if err != nil {
		return Claims{}, err
	}
	if err := a.validateChain(p.claims.TokenID, at, map[string]bool{}); err != nil {
		return Claims{}, err
	}
	return p.claims, nil
}

// parseAndLookup parses raw and returns its stored record. It does not verify
// the chain; callers must hold at least a read lock.
func (a *Authority) parseAndLookup(raw string) (*record, error) {
	parsed, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	rec, ok := a.records[parsed.Claims.TokenID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownToken, shortID(parsed.Claims.TokenID))
	}
	// Guard against presenting a different raw string that happens to carry
	// the same token id: the stored copy is the authoritative serialization.
	if rec.raw != raw {
		return nil, fmt.Errorf("%w: token content does not match issuance record", ErrBadSignature)
	}
	return rec, nil
}

// validateChain recursively validates the chain rooted at id. The seen set
// defends against corrupt (cyclic) registry state.
//
// For every node it checks, in order:
//  1. the node exists and is not revoked,
//  2. the node is not expired at at,
//  3. its signature verifies under the correct key (its own for the root,
//     its parent's otherwise),
//  4. delegation constraints against its parent (subset caps, exp <= parent),
//
// and then recurses into the parent.
func (a *Authority) validateChain(id string, at time.Time, seen map[string]bool) error {
	if seen[id] {
		return fmt.Errorf("%w: cycle at %s", ErrChainBroken, shortID(id))
	}
	seen[id] = true

	rec, ok := a.records[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownToken, shortID(id))
	}
	if rec.revoked {
		return fmt.Errorf("%w: %s", ErrTokenRevoked, shortID(id))
	}
	if rec.claims.Expired(at) {
		return fmt.Errorf("%w: %s", ErrTokenExpired, shortID(id))
	}

	parsed, err := Parse(rec.raw)
	if err != nil { // cannot happen for registry-issued tokens
		return fmt.Errorf("%w: stored token unparseable", ErrChainBroken)
	}

	if rec.claims.ParentID == "" {
		// Root: must be the authority's root, self-signed, kid == tid.
		if id != a.rootID {
			return fmt.Errorf("%w: unregistered root %s", ErrChainBroken, shortID(id))
		}
		if parsed.Header.Kid != id {
			return fmt.Errorf("%w: root not self-signed", ErrRootNotSelf)
		}
		if !parsed.verifySignature(rec.key.Public) {
			return fmt.Errorf("%w: root signature", ErrBadSignature)
		}
		return nil
	}

	parent, ok := a.records[rec.claims.ParentID]
	if !ok {
		return fmt.Errorf("%w: missing parent %s", ErrChainBroken, shortID(rec.claims.ParentID))
	}
	// Signature must verify against the PARENT's public key, and the header
	// kid must name that key.
	if parsed.Header.Kid != parent.claims.TokenID {
		return fmt.Errorf("%w: signer key id does not match parent", ErrParentKeyMismatch)
	}
	var parentPub ed25519.PublicKey = parent.key.Public
	if !parsed.verifySignature(parentPub) {
		return fmt.Errorf("%w: signature by %s over %s",
			ErrBadSignature, shortID(parent.claims.TokenID), shortID(id))
	}
	// Constraints are enforced from the stored claims, independent of
	// whatever the presented token claimed.
	if !rec.claims.Caps.IsSubsetOf(parent.claims.Caps) {
		return fmt.Errorf("%w: %s exceeds %s",
			ErrCapabilityEscalation, shortID(id), shortID(parent.claims.TokenID))
	}
	if rec.claims.Exp > parent.claims.Exp {
		return fmt.Errorf("%w: %s outlives %s",
			ErrExpiryExtended, shortID(id), shortID(parent.claims.TokenID))
	}
	return a.validateChain(parent.claims.TokenID, at, seen)
}

// --- Visualization snapshot -------------------------------------------------

// NodeStatus classifies a node for visualization.
type NodeStatus string

const (
	StatusValid           NodeStatus = "valid"
	StatusRevoked         NodeStatus = "revoked"
	StatusAncestorRevoked NodeStatus = "blocked_revoked" // invalid because an ancestor is revoked
	StatusExpired         NodeStatus = "expired"
)

// NodeView is one token in an export snapshot.
type NodeView struct {
	ID        string       `json:"id"`
	ShortID   string       `json:"shortId"`
	ParentID  string       `json:"parentId,omitempty"`
	Issuer    string       `json:"issuer"`
	Caps      Capabilities `json:"caps"`
	Iat       int64        `json:"iat"`
	Exp       int64        `json:"exp"`
	Depth     int          `json:"depth"`
	Revoked   bool         `json:"revoked"`
	RevokedAt int64        `json:"revokedAt,omitempty"`
	Status    NodeStatus   `json:"status"`
	// Raw is the serialized header.payload.signature token.
	Raw string `json:"raw"`
	// BlockedBy is the id of the revoked ancestor when Status is
	// blocked_revoked.
	BlockedBy string `json:"blockedBy,omitempty"`
}

// Snapshot is a serializable view of the whole delegation tree.
type Snapshot struct {
	RootID      string     `json:"rootId"`
	RootShortID string     `json:"rootShortId"`
	GeneratedAt int64      `json:"generatedAt"`
	Nodes       []NodeView `json:"nodes"`
}

// SnapshotAt computes a tree view as of time at. Nodes are returned in
// issuance order, parents always before children.
func (a *Authority) SnapshotAt(at time.Time) Snapshot {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// Depth via parent walk; insertion order is issuance order and parents
	// are always inserted before their children.
	ids := make([]string, 0, len(a.records))
	for id := range a.records {
		ids = append(ids, id)
	}
	// Stable, parent-before-child ordering: sort by iat then id.
	sortIDsByIssuance(ids, a.records)

	depth := map[string]int{}
	var depthOf func(string) int
	depthOf = func(id string) int {
		if d, ok := depth[id]; ok {
			return d
		}
		rec := a.records[id]
		if rec.claims.ParentID == "" {
			depth[id] = 0
			return 0
		}
		d := depthOf(rec.claims.ParentID) + 1
		depth[id] = d
		return d
	}

	nodes := make([]NodeView, 0, len(ids))
	for _, id := range ids {
		rec := a.records[id]
		view := NodeView{
			ID:        id,
			ShortID:   shortID(id),
			ParentID:  rec.claims.ParentID,
			Issuer:    rec.claims.Issuer,
			Caps:      append(Capabilities{}, rec.claims.Caps...),
			Iat:       rec.claims.Iat,
			Exp:       rec.claims.Exp,
			Depth:     depthOf(id),
			Revoked:   rec.revoked,
			RevokedAt: rec.revokedAt,
			Status:    StatusValid,
			Raw:       rec.raw,
		}
		switch {
		case rec.revoked:
			view.Status = StatusRevoked
		case rec.claims.Expired(at):
			view.Status = StatusExpired
		default:
			// Walk ancestors: a revoked ancestor blocks the whole subtree;
			// an expired ancestor (given exp monotonicity) means this node is
			// expired as well.
			cur := rec.claims.ParentID
			for cur != "" {
				anc := a.records[cur]
				if anc.revoked {
					view.Status = StatusAncestorRevoked
					view.BlockedBy = cur
					break
				}
				cur = anc.claims.ParentID
			}
		}
		nodes = append(nodes, view)
	}
	return Snapshot{
		RootID:      a.rootID,
		RootShortID: shortID(a.rootID),
		GeneratedAt: at.Unix(),
		Nodes:       nodes,
	}
}

// Snapshot is SnapshotAt at the current time.
func (a *Authority) Snapshot() Snapshot {
	return a.SnapshotAt(a.now())
}

// shortID renders the first 12 characters of an id for display.
func shortID(id string) string {
	if len(id) <= 12 {
		return id
	}
	return id[:12]
}

// looksLikeToken distinguishes raw tokens (header.payload.signature) from ids.
func looksLikeToken(s string) bool {
	dots := 0
	for _, r := range s {
		if r == '.' {
			dots++
		}
	}
	return dots == 2
}
