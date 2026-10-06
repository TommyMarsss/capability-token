// Command demo builds a representative delegation tree, performs a
// mid-tree revocation (proving subtree propagation without affecting sibling
// branches), records the delegation requests that issuance correctly
// rejected, and renders everything into a single self-contained report.html.
//
// It does NOT start a server: the output is a static file you can open
// directly in a browser.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	_ "embed"

	cap "github.com/TommyMarsss/capability-token"
)

//go:embed template.html
var templateHTML string

// RejectedAttempt records one issuance request the authority refused, for the
// audit panel in the generated page.
type RejectedAttempt struct {
	Kind   string   `json:"kind"`
	Parent string   `json:"parent"`
	Issuer string   `json:"issuer"`
	Caps   []string `json:"caps"`
	Exp    int64    `json:"exp"`
	Error  string   `json:"error"`
}

func main() {
	out := flag.String("out", "report.html", "output HTML file")
	flag.Parse()

	// Fixed clock keeps the generated page deterministic.
	base := time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)
	clock := func() time.Time { return base }

	// ---- Root: full power ---------------------------------------------------
	auth, root, err := cap.NewRoot(
		"组织根令牌 ROOT",
		[]string{"doc:read", "doc:write", "doc:delete", "user:admin"},
		base.Add(72*time.Hour),
		cap.WithClock(clock),
	)
	must(err)

	// ---- Branch A: editorial ------------------------------------------------
	editorA, err := auth.Delegate(root, "编辑部主管 Alice",
		[]string{"doc:read", "doc:write"}, base.Add(48*time.Hour))
	must(err)

	editorA1, err := auth.Delegate(editorA, "编辑 A1 · Bob",
		[]string{"doc:read", "doc:write"}, base.Add(24*time.Hour))
	must(err)

	reviewerA2, err := auth.Delegate(editorA, "审核员 A2 · Carol",
		[]string{"doc:read"}, base.Add(24*time.Hour))
	must(err)

	intern, err := auth.Delegate(editorA1, "实习编辑 A1-a · Dave",
		[]string{"doc:read"}, base.Add(12*time.Hour))
	must(err)

	// Fourth-level descendant of the node we are about to revoke.
	outsider, err := auth.Delegate(intern, "外包读者 A1-a-x · Erin",
		[]string{"doc:read"}, base.Add(6*time.Hour))
	must(err)

	// ---- Branch B: ops (independent of the revoked subtree) -----------------
	opsB, err := auth.Delegate(root, "运维主管 Bruce",
		[]string{"doc:read", "user:admin"}, base.Add(48*time.Hour))
	must(err)
	patrolB1, err := auth.Delegate(opsB, "只读巡检 B1 · Faye",
		[]string{"doc:read"}, base.Add(24*time.Hour))
	must(err)

	// ---- Revoke the intern: intern + outsider must die; nothing else --------
	must(auth.Revoke(intern))

	// Sanity-check the propagation story before rendering it.
	expectInvalid(auth, intern, "revoked intern")
	expectInvalid(auth, outsider, "descendant of revoked intern")
	for name, raw := range map[string]string{
		"root":       root,
		"editorA":    editorA,
		"editorA1":   editorA1,
		"reviewerA2": reviewerA2,
		"opsB":       opsB,
		"patrolB1":   patrolB1,
	} {
		if _, err := auth.Verify(raw); err != nil {
			log.Fatalf("healthy token %s unexpectedly invalid: %v", name, err)
		}
	}

	// ---- Rejected issuance requests ----------------------------------------
	var attempts []RejectedAttempt

	// 1. Capability escalation: Bob has read/write but asks for delete.
	_, err = auth.Delegate(editorA1, "提权尝试者 Mallory",
		[]string{"doc:read", "doc:delete"}, base.Add(8*time.Hour))
	attempts = append(attempts, recordAttempt("权限扩大被拒绝",
		"编辑 A1 · Bob", "提权尝试者 Mallory",
		[]string{"doc:read", "doc:delete"}, base.Add(8*time.Hour), err))

	// 2. Capability escalation across namespaces: an editor asks for user:admin.
	_, err = auth.Delegate(editorA, "越权尝试者 Nygel",
		[]string{"user:admin"}, base.Add(10*time.Hour))
	attempts = append(attempts, recordAttempt("权限扩大被拒绝",
		"编辑部主管 Alice", "越权尝试者 Nygel",
		[]string{"user:admin"}, base.Add(10*time.Hour), err))

	// 3. Expiry extension: Carol's token expires in 24h; she tries 60h.
	_, err = auth.Delegate(reviewerA2, "延期尝试者 Oscar",
		[]string{"doc:read"}, base.Add(60*time.Hour))
	attempts = append(attempts, recordAttempt("有效期延长被拒绝",
		"审核员 A2 · Carol", "延期尝试者 Oscar",
		[]string{"doc:read"}, base.Add(60*time.Hour), err))

	// ---- Render -------------------------------------------------------------
	snapshot := auth.SnapshotAt(base.Add(1 * time.Hour))
	snapJSON, err := json.Marshal(snapshot)
	must(err)
	attJSON, err := json.Marshal(attempts)
	must(err)

	html := strings.NewReplacer(
		"__SNAPSHOT__", string(snapJSON),
		"__ATTEMPTS__", string(attJSON),
	).Replace(templateHTML)

	must(os.WriteFile(*out, []byte(html), 0o644))
	fmt.Printf("wrote %s (%d tokens, %d rejected delegation attempts)\n",
		*out, len(snapshot.Nodes), len(attempts))
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func expectInvalid(a *cap.Authority, raw, name string) {
	if _, err := a.Verify(raw); err == nil {
		log.Fatalf("%s: expected token to be invalid, but Verify succeeded", name)
	} else {
		fmt.Printf("ok: %-34s -> %v\n", name, err)
	}
}

func recordAttempt(kind, parent, issuer string, caps []string, exp time.Time, err error) RejectedAttempt {
	if err == nil {
		log.Fatalf("expected %q request to be rejected, but it succeeded", kind)
	}
	return RejectedAttempt{
		Kind:   kind,
		Parent: parent,
		Issuer: issuer,
		Caps:   cap.NewCapabilities(caps...),
		Exp:    exp.Unix(),
		Error:  err.Error(),
	}
}
