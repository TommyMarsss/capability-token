package capability_test

import (
	"sync"
	"testing"
	"time"
)

// Concurrent issuance, verification and revocation must not race.
func TestAuthorityConcurrentAccess(t *testing.T) {
	a, root := mustRoot(t)
	base := clock2(a)

	var wg sync.WaitGroup
	leaf := make(chan string, 32)

	// Issuers
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			raw, err := a.Delegate(root, "worker", []string{"doc:read"}, base.Add(12*time.Hour))
			if err == nil {
				leaf <- raw
			}
		}(i)
	}
	// Verifiers
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_, _ = a.Verify(root)
			}
		}()
	}
	wg.Wait()
	close(leaf)

	// Revoke every issued leaf concurrently with one more round of verifies.
	var wg2 sync.WaitGroup
	for raw := range leaf {
		raw := raw
		wg2.Add(2)
		go func() { defer wg2.Done(); _ = a.Revoke(raw) }()
		go func() { defer wg2.Done(); _, _ = a.Verify(raw) }()
	}
	wg2.Wait()
}
