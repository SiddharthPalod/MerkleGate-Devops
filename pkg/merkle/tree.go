package merkle

import (
	"errors"
	"math/bits"
)

type Node struct {
	Hash   []byte
	Left   *Node
	Right  *Node
	Parent *Node
}

type Tree struct {
	Root   *Node
	Leaves []*Node
	hasher Hasher
}

func NewTree(leavesData [][]byte, hasher Hasher) (*Tree, error) {
	if hasher == nil {
		return nil, errors.New("hasher cannot be nil")
	}

	n := len(leavesData)
	if n == 0 {
		return &Tree{
			Root:   &Node{Hash: hasher.EmptyRoot()},
			Leaves: nil,
			hasher: hasher,
		}, nil
	}

	leaves := make([]*Node, n)
	for i, d := range leavesData {
		leaves[i] = &Node{Hash: hasher.HashLeaf(d)}
	}

	if n == 1 {
		return &Tree{
			Root:   leaves[0],
			Leaves: leaves,
			hasher: hasher,
		}, nil
	}

	root := buildSubtree(leaves, hasher)
	return &Tree{
		Root:   root,
		Leaves: leaves,
		hasher: hasher,
	}, nil
}

func buildSubtree(nodes []*Node, hasher Hasher) *Node {
	n := len(nodes)
	if n == 1 {
		return nodes[0]
	}

	k := splitPoint(n)
	left := buildSubtree(nodes[:k], hasher)
	right := buildSubtree(nodes[k:], hasher)

	parent := &Node{
		Hash:  hasher.HashChildren(left.Hash, right.Hash),
		Left:  left,
		Right: right,
	}
	left.Parent = parent
	right.Parent = parent

	return parent
}

func splitPoint(n int) int {
	if n < 2 {
		return 0
	}
	return 1 << (bits.Len(uint(n-1)) - 1)
}
