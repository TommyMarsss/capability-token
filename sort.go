package capability

import "sort"

// sortIDsByIssuance orders ids so that every parent precedes its children.
// Issuance timestamp (iat) is monotonic along a chain and strictly increasing
// at issue time, so sorting by iat then id yields the required order.
func sortIDsByIssuance(ids []string, records map[string]*record) {
	sort.Slice(ids, func(i, j int) bool {
		ri, rj := records[ids[i]], records[ids[j]]
		if ri.claims.Iat != rj.claims.Iat {
			return ri.claims.Iat < rj.claims.Iat
		}
		return ids[i] < ids[j]
	})
}
