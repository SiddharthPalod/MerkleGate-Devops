package merkle

import (
	"bytes"
	"testing"
)

func TestSplitPoint(t *testing.T) {
	cases := []struct {
		n        int
		expected int
	}{
		{2, 1},
		{3, 2},
		{4, 2},
		{5, 4},
		{6, 4},
		{7, 4},
		{8, 4},
		{9, 8},
		{16, 8},
		{17, 16},
	}

	for _, c := range cases {
		got := splitPoint(c.n)
		if got != c.expected {
			t.Errorf("splitPoint(%d) = %d, expected %d", c.n, got, c.expected)
		}
	}
}

func TestNewTree_Empty(t *testing.T) {
	hasher := NewSHA256Hasher()
	tree, err := NewTree(nil, hasher)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Equal(tree.Root.Hash, hasher.EmptyRoot()) {
		t.Fatalf("root hash mismatch for empty tree")
	}
	if len(tree.Leaves) != 0 {
		t.Fatalf("expected 0 leaves, got %d", len(tree.Leaves))
	}
}

func TestNewTree_SingleLeaf(t *testing.T) {
	hasher := NewSHA256Hasher()
	data := [][]byte{[]byte("event_1")}
	tree, err := NewTree(data, hasher)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedRoot := hasher.HashLeaf(data[0])
	if !bytes.Equal(tree.Root.Hash, expectedRoot) {
		t.Fatalf("root hash mismatch for single leaf")
	}
	if tree.Root != tree.Leaves[0] {
		t.Fatalf("expected Root to be the single leaf node")
	}
	if tree.Root.Parent != nil {
		t.Fatalf("expected single leaf parent to be nil")
	}
}

func TestNewTree_MultipleLeaves(t *testing.T) {
	hasher := NewSHA256Hasher()
	data := [][]byte{
		[]byte("e0"),
		[]byte("e1"),
		[]byte("e2"),
	}

	tree, err := NewTree(data, hasher)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(tree.Leaves) != 3 {
		t.Fatalf("expected 3 leaves, got %d", len(tree.Leaves))
	}

	// For n=3, k=2: left is (e0, e1), right is (e2)
	h0 := hasher.HashLeaf(data[0])
	h1 := hasher.HashLeaf(data[1])
	h2 := hasher.HashLeaf(data[2])

	h01 := hasher.HashChildren(h0, h1)
	expectedRoot := hasher.HashChildren(h01, h2)

	if !bytes.Equal(tree.Root.Hash, expectedRoot) {
		t.Fatalf("root hash mismatch for n=3: got %x, expected %x", tree.Root.Hash, expectedRoot)
	}

	// Verify parent pointers
	if tree.Leaves[0].Parent.Parent != tree.Root {
		t.Fatalf("tree.Leaves[0] parent pointer chain broken")
	}
	if tree.Leaves[2].Parent != tree.Root {
		t.Fatalf("tree.Leaves[2] parent pointer broken")
	}
}
