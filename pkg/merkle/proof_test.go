package merkle

import (
	"fmt"
	"testing"
)

func TestInclusionProof_Sizes(t *testing.T) {
	hasher := NewSHA256Hasher()

	testSizes := []int{1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 31, 32, 63, 64, 100}

	for _, size := range testSizes {
		t.Run(fmt.Sprintf("Size_%d", size), func(t *testing.T) {
			leaves := make([][]byte, size)
			for i := 0; i < size; i++ {
				leaves[i] = []byte(fmt.Sprintf("event-data-%d-%d", size, i))
			}

			tree, err := NewTree(leaves, hasher)
			if err != nil {
				t.Fatalf("failed to create tree: %v", err)
			}

			for i := 0; i < size; i++ {
				proof, err := tree.GenerateInclusionProof(i)
				if err != nil {
					t.Fatalf("failed to generate proof for leaf %d: %v", i, err)
				}

				leafHash := hasher.HashLeaf(leaves[i])
				if !VerifyInclusion(hasher, leafHash, tree.Root.Hash, proof) {
					t.Fatalf("failed to verify valid inclusion proof for leaf %d in tree size %d", i, size)
				}
			}
		})
	}
}

func TestInclusionProof_TamperResistance(t *testing.T) {
	hasher := NewSHA256Hasher()
	leaves := [][]byte{
		[]byte("commit_sha_1"),
		[]byte("commit_sha_2"),
		[]byte("scan_result_pass"),
		[]byte("approval_alice"),
		[]byte("approval_bob"),
	}

	tree, err := NewTree(leaves, hasher)
	if err != nil {
		t.Fatalf("failed to create tree: %v", err)
	}

	proof, err := tree.GenerateInclusionProof(2)
	if err != nil {
		t.Fatalf("failed to generate proof: %v", err)
	}

	validLeafHash := hasher.HashLeaf(leaves[2])

	// 1. Valid leaf must pass
	if !VerifyInclusion(hasher, validLeafHash, tree.Root.Hash, proof) {
		t.Fatal("expected valid proof to pass")
	}

	// 2. Tampered leaf payload (single bit flip) must fail
	tamperedLeaf := append([]byte(nil), leaves[2]...)
	tamperedLeaf[0] ^= 0x01
	tamperedLeafHash := hasher.HashLeaf(tamperedLeaf)
	if VerifyInclusion(hasher, tamperedLeafHash, tree.Root.Hash, proof) {
		t.Fatal("tampered leaf hash passed verification")
	}

	// 3. Tampered audit path sibling must fail
	tamperedProof := &InclusionProof{
		LeafIndex: proof.LeafIndex,
		TreeSize:  proof.TreeSize,
		AuditPath: make([][]byte, len(proof.AuditPath)),
	}
	for i, p := range proof.AuditPath {
		tamperedProof.AuditPath[i] = append([]byte(nil), p...)
	}
	tamperedProof.AuditPath[0][0] ^= 0x01
	if VerifyInclusion(hasher, validLeafHash, tree.Root.Hash, tamperedProof) {
		t.Fatal("tampered audit path passed verification")
	}

	// 4. Tampered root must fail
	tamperedRoot := append([]byte(nil), tree.Root.Hash...)
	tamperedRoot[0] ^= 0x01
	if VerifyInclusion(hasher, validLeafHash, tamperedRoot, proof) {
		t.Fatal("tampered root passed verification")
	}

	// 5. Wrong leaf index must fail
	wrongIndexProof := &InclusionProof{
		LeafIndex: (proof.LeafIndex + 1) % proof.TreeSize,
		TreeSize:  proof.TreeSize,
		AuditPath: proof.AuditPath,
	}
	if VerifyInclusion(hasher, validLeafHash, tree.Root.Hash, wrongIndexProof) {
		t.Fatal("wrong leaf index passed verification")
	}
}
