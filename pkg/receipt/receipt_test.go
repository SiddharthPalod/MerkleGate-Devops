package receipt

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"merklegate/pkg/merkle"
	"merklegate/pkg/signer"
)

func setupTestEnvironment(t *testing.T) (ed25519.PublicKey, *signer.LocalSigner, merkle.Hasher) {
	pub, priv, err := signer.GenerateKeypair()
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}
	sig := signer.NewLocalSigner(priv)
	hasher := merkle.NewSHA256Hasher()
	return pub, sig, hasher
}

func TestReceipt_SameTreeSize(t *testing.T) {
	pubKey, sig, hasher := setupTestEnvironment(t)

	events := [][]byte{
		[]byte(`{"event_type":"git_commit","commit_sha":"a1b2c3d","actor":"alice"}`),
		[]byte(`{"event_type":"snyk_scan","commit_sha":"a1b2c3d","actor":"snyk-bot"}`),
		[]byte(`{"event_type":"pr_approval","pr_number":42,"actor":"bob"}`),
		[]byte(`{"event_type":"argocd_sync","commit_sha":"a1b2c3d","actor":"argocd"}`),
	}

	tree, err := merkle.NewTree(events, hasher)
	if err != nil {
		t.Fatalf("failed to build tree: %v", err)
	}

	sth, err := sig.SignTreeHead(len(events), tree.Root.Hash, 1)
	if err != nil {
		t.Fatalf("failed to sign STH: %v", err)
	}

	// Generate receipt for leaf index 1 (snyk_scan)
	leafIdx := 1
	inclProof, err := tree.GenerateInclusionProof(leafIdx)
	if err != nil {
		t.Fatalf("failed to generate inclusion proof: %v", err)
	}

	receipt, err := BuildReceipt(leafIdx, events[leafIdx], inclProof, nil, nil, sth)
	if err != nil {
		t.Fatalf("failed to build receipt: %v", err)
	}

	report := Verify(pubKey, receipt)
	if !report.Valid {
		t.Fatalf("expected receipt to be valid, got error: %s", report.Error)
	}

	if len(report.Steps) != 3 {
		t.Fatalf("expected 3 verification steps for same size tree, got %d", len(report.Steps))
	}
}

func TestReceipt_CompositeHistoricalGrowth(t *testing.T) {
	pubKey, sig, hasher := setupTestEnvironment(t)

	// Historical tree at size 4
	historicalEvents := [][]byte{
		[]byte(`{"event_type":"git_commit","commit_sha":"commit1","actor":"alice"}`),
		[]byte(`{"event_type":"snyk_scan","commit_sha":"commit1","actor":"snyk-bot"}`),
		[]byte(`{"event_type":"pr_approval","pr_number":10,"actor":"bob"}`),
		[]byte(`{"event_type":"argocd_sync","commit_sha":"commit1","actor":"argocd"}`),
	}
	oldTree, _ := merkle.NewTree(historicalEvents, hasher)

	// Leaf 2 (pr_approval) committed in Tree(4)
	leafIdx := 2
	inclProof, err := oldTree.GenerateInclusionProof(leafIdx)
	if err != nil {
		t.Fatalf("failed to generate inclusion proof: %v", err)
	}

	// Ledger grows to size 7
	allEvents := append(historicalEvents,
		[]byte(`{"event_type":"git_commit","commit_sha":"commit2","actor":"carol"}`),
		[]byte(`{"event_type":"snyk_scan","commit_sha":"commit2","actor":"snyk-bot"}`),
		[]byte(`{"event_type":"pr_approval","pr_number":11,"actor":"dave"}`),
	)
	newTree, _ := merkle.NewTree(allEvents, hasher)

	// Consistency proof between oldTree (4) and newTree (7)
	constProof, err := newTree.GenerateConsistencyProof(4)
	if err != nil {
		t.Fatalf("failed to generate consistency proof: %v", err)
	}

	sth, err := sig.SignTreeHead(7, newTree.Root.Hash, 2)
	if err != nil {
		t.Fatalf("failed to sign STH: %v", err)
	}

	receipt, err := BuildReceipt(leafIdx, historicalEvents[leafIdx], inclProof, constProof, oldTree.Root.Hash, sth)
	if err != nil {
		t.Fatalf("failed to build composite receipt: %v", err)
	}

	report := Verify(pubKey, receipt)
	if !report.Valid {
		t.Fatalf("expected composite receipt to be valid, got error: %s", report.Error)
	}

	if len(report.Steps) != 4 {
		t.Fatalf("expected 4 verification steps (including consistency proof), got %d", len(report.Steps))
	}
}

func TestReceipt_TamperResistance(t *testing.T) {
	pubKey, sig, hasher := setupTestEnvironment(t)

	events := [][]byte{
		[]byte(`{"event_type":"git_commit","commit_sha":"sec1","actor":"alice"}`),
		[]byte(`{"event_type":"snyk_scan","commit_sha":"sec1","status":"clean"}`),
	}
	tree, _ := merkle.NewTree(events, hasher)
	sth, _ := sig.SignTreeHead(2, tree.Root.Hash, 1)

	inclProof, _ := tree.GenerateInclusionProof(1)
	baseReceipt, _ := BuildReceipt(1, events[1], inclProof, nil, nil, sth)

	// Test 1: Tamper raw event payload (e.g. attacker alters "clean" to "vuln")
	t.Run("PayloadTamperFails", func(t *testing.T) {
		tampered := *baseReceipt
		tampered.RawPayload = `{"event_type":"snyk_scan","commit_sha":"sec1","status":"backdoor"}`
		report := Verify(pubKey, &tampered)
		if report.Valid {
			t.Fatal("expected payload tamper to fail verification")
		}
	})

	// Test 2: Tamper audit sibling hash
	t.Run("AuditPathTamperFails", func(t *testing.T) {
		tampered := *baseReceipt
		tampered.InclusionProof.AuditPath = []string{"deadbeef00000000000000000000000000000000000000000000000000000000"}
		report := Verify(pubKey, &tampered)
		if report.Valid {
			t.Fatal("expected audit path tamper to fail verification")
		}
	})

	// Test 3: Rogue public key (signed by legitimate server, verified against untrusted key)
	t.Run("UntrustedPublicKeyFails", func(t *testing.T) {
		roguePub, _, _ := signer.GenerateKeypair()
		report := Verify(roguePub, baseReceipt)
		if report.Valid {
			t.Fatal("expected verification with untrusted public key to fail")
		}
	})

	// Test 4: Tamper STH Root Hash
	t.Run("STHRootTamperFails", func(t *testing.T) {
		tampered := *baseReceipt
		badRoot := make([]byte, 32)
		copy(badRoot, []byte("tampered-root-hash-tampered-root"))
		tampered.SignedTreeHead.RootHash = hex.EncodeToString(badRoot)
		report := Verify(pubKey, &tampered)
		if report.Valid {
			t.Fatal("expected STH root tamper to fail verification")
		}
	})
}
