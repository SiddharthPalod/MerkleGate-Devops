package merkle

import (
	"fmt"
	"testing"
)

func TestConsistencyProof_Valid(t *testing.T) {
	hasher := NewSHA256Hasher()

	allLeaves := make([][]byte, 10)
	for i := 0; i < 10; i++ {
		allLeaves[i] = []byte(fmt.Sprintf("event-%d", i))
	}

	// Build the full tree once (n=10), then verify consistency from every old size m=[1..10]
	fullTree, err := NewTree(allLeaves, hasher)
	if err != nil {
		t.Fatalf("failed to build full tree: %v", err)
	}

	for m := 1; m <= 10; m++ {
		oldTree, err := NewTree(allLeaves[:m], hasher)
		if err != nil {
			t.Fatalf("failed to build old tree of size %d: %v", m, err)
		}

		proof, err := fullTree.GenerateConsistencyProof(m)
		if err != nil {
			t.Fatalf("failed to generate consistency proof from size %d to 10: %v", m, err)
		}

		if !VerifyConsistency(hasher, oldTree.Root.Hash, fullTree.Root.Hash, proof) {
			t.Fatalf("consistency proof failed for m=%d, n=10", m)
		}
	}
}

func TestConsistencyProof_SameSize(t *testing.T) {
	hasher := NewSHA256Hasher()
	leaves := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
	tree, _ := NewTree(leaves, hasher)

	proof, err := tree.GenerateConsistencyProof(3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !VerifyConsistency(hasher, tree.Root.Hash, tree.Root.Hash, proof) {
		t.Fatal("consistency proof for same-size tree failed")
	}
}

func TestConsistencyProof_TamperResistance(t *testing.T) {
	hasher := NewSHA256Hasher()

	leaves := make([][]byte, 8)
	for i := range leaves {
		leaves[i] = []byte(fmt.Sprintf("event-%d", i))
	}

	oldTree, _ := NewTree(leaves[:4], hasher)
	fullTree, _ := NewTree(leaves, hasher)

	proof, err := fullTree.GenerateConsistencyProof(4)
	if err != nil {
		t.Fatalf("failed to generate proof: %v", err)
	}

	// Valid baseline
	if !VerifyConsistency(hasher, oldTree.Root.Hash, fullTree.Root.Hash, proof) {
		t.Fatal("expected valid consistency proof to pass")
	}

	// Tampered old root
	tamperedOld := append([]byte(nil), oldTree.Root.Hash...)
	tamperedOld[0] ^= 0x01
	if VerifyConsistency(hasher, tamperedOld, fullTree.Root.Hash, proof) {
		t.Fatal("tampered old root passed consistency verification")
	}

	// Tampered new root
	tamperedNew := append([]byte(nil), fullTree.Root.Hash...)
	tamperedNew[0] ^= 0x01
	if VerifyConsistency(hasher, oldTree.Root.Hash, tamperedNew, proof) {
		t.Fatal("tampered new root passed consistency verification")
	}

	// Tampered proof path node
	tamperedProof := &ConsistencyProof{
		FirstSize:  proof.FirstSize,
		SecondSize: proof.SecondSize,
		Path:       make([][]byte, len(proof.Path)),
	}
	for i, p := range proof.Path {
		tamperedProof.Path[i] = append([]byte(nil), p...)
	}
	tamperedProof.Path[0][0] ^= 0x01
	if VerifyConsistency(hasher, oldTree.Root.Hash, fullTree.Root.Hash, tamperedProof) {
		t.Fatal("tampered proof path passed consistency verification")
	}
}

func TestConsistencyProof_PropertyBased_TamperInvalidatesRoot(t *testing.T) {
	hasher := NewSHA256Hasher()

	for n := 2; n <= 32; n++ {
		leaves := make([][]byte, n)
		for i := 0; i < n; i++ {
			leaves[i] = []byte(fmt.Sprintf("e-%d-%d", n, i))
		}
		fullTree, _ := NewTree(leaves, hasher)

		for m := 1; m < n; m++ {
			oldTree, _ := NewTree(leaves[:m], hasher)

			proof, err := fullTree.GenerateConsistencyProof(m)
			if err != nil {
				t.Fatalf("n=%d m=%d: failed to generate consistency proof: %v", n, m, err)
			}

			if !VerifyConsistency(hasher, oldTree.Root.Hash, fullTree.Root.Hash, proof) {
				t.Fatalf("n=%d m=%d: valid consistency proof failed", n, m)
			}

			// Single-bit flip in event at index 0 must change both old and new roots
			leaves[0][0] ^= 0x01
			tamperedOldTree, _ := NewTree(leaves[:m], hasher)
			tamperedFullTree, _ := NewTree(leaves, hasher)

			if VerifyConsistency(hasher, oldTree.Root.Hash, tamperedFullTree.Root.Hash, proof) {
				t.Fatalf("n=%d m=%d: tampered data passed consistency verification", n, m)
			}
			if VerifyConsistency(hasher, tamperedOldTree.Root.Hash, fullTree.Root.Hash, proof) {
				t.Fatalf("n=%d m=%d: tampered old root passed verification", n, m)
			}

			// Restore
			leaves[0][0] ^= 0x01
		}
	}
}
