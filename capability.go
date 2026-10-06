// Package capability implements a capability-based access control and token
// delegation system built on signed delegation chains.
//
// A root token is self-signed; every child token is signed by its parent's
// private key and may only carry a subset of the parent's capabilities and an
// expiry no later than the parent's. Verification walks the signature chain
// recursively to the root, and revocation of any token instantly invalidates
// the entire subtree below it.
package capability

import (
	"sort"
	"strings"
)

// Capabilities is a canonical, deduplicated, lexicographically sorted set of
// capability identifiers (for example "doc:read" or "user:admin").
//
// The sorted representation makes JSON encoding deterministic, which is a
// prerequisite for stable signing: the exact byte sequence that was signed is
// the exact byte sequence verified.
type Capabilities []string

// NewCapabilities builds a canonical capability set: whitespace is trimmed,
// empty entries are dropped, duplicates are removed and the result is sorted.
func NewCapabilities(caps ...string) Capabilities {
	set := make(map[string]struct{}, len(caps))
	for _, c := range caps {
		if c = strings.TrimSpace(c); c != "" {
			set[c] = struct{}{}
		}
	}
	out := make(Capabilities, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Contains reports whether c is present. The receiver is sorted, so the
// lookup is logarithmic.
func (cs Capabilities) Contains(c string) bool {
	i := sort.SearchStrings(cs, c)
	return i < len(cs) && cs[i] == c
}

// IsSubsetOf reports whether every capability in cs is also present in
// parent. An empty set is a subset of every set (including the empty set).
func (cs Capabilities) IsSubsetOf(parent Capabilities) bool {
	j := 0
	for _, c := range cs {
		for j < len(parent) && parent[j] < c {
			j++
		}
		if j == len(parent) || parent[j] != c {
			return false
		}
	}
	return true
}

// Equal reports whether the two sets contain exactly the same capabilities.
func (cs Capabilities) Equal(other Capabilities) bool {
	return cs.IsSubsetOf(other) && other.IsSubsetOf(cs)
}

// String renders the set as "[a b c]" in its canonical (sorted) order; it is
// mainly useful in error messages and tests.
func (cs Capabilities) String() string {
	return "[" + strings.Join(cs, " ") + "]"
}
