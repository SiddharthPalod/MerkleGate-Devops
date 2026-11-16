package merkle

import (
	"bytes"
	"errors"
	"math/bits"
)

type ConsistencyProof struct {
	FirstSize  int
	SecondSize int
	Path       [][]byte
}

func (t *Tree) GenerateConsistencyProof(oldSize int) (*ConsistencyProof, error) {
	n := len(t.Leaves)
	if oldSize <= 0 || oldSize > n {
		return nil, errors.New("oldSize must be in range [1, treeSize]")
	}
	if n == 0 {
		return nil, errors.New("cannot generate consistency proof for empty tree")
	}
	if oldSize == n {
		return &ConsistencyProof{FirstSize: oldSize, SecondSize: n, Path: nil}, nil
	}

	path := consistencyNodes(oldSize, n, t.Root, true)
	return &ConsistencyProof{
		FirstSize:  oldSize,
		SecondSize: n,
		Path:       path,
	}, nil
}

func consistencyNodes(m, n int, node *Node, startFromRoot bool) [][]byte {
	if m == n {
		if startFromRoot {
			return nil
		}
		return [][]byte{node.Hash}
	}

	k := splitPoint(n)
	if m <= k {
		path := consistencyNodes(m, k, node.Left, startFromRoot)
		return append(path, node.Right.Hash)
	}

	path := consistencyNodes(m-k, n-k, node.Right, false)
	return append(path, node.Left.Hash)
}

// VerifyConsistency implements RFC 6962 / RFC 9162 Section 2.1.4.2 consistency verification.
func VerifyConsistency(hasher Hasher, oldRoot, newRoot []byte, proof *ConsistencyProof) bool {
	if hasher == nil || proof == nil || len(oldRoot) == 0 || len(newRoot) == 0 {
		return false
	}
	m, n := proof.FirstSize, proof.SecondSize
	if m <= 0 || n <= 0 || m > n {
		return false
	}
	if m == n {
		return bytes.Equal(oldRoot, newRoot) && len(proof.Path) == 0
	}
	if len(proof.Path) == 0 {
		return false
	}

	path := make([][]byte, len(proof.Path))
	copy(path, proof.Path)

	// Step 2: If first is an exact power of 2, prepend oldRoot
	if bits.OnesCount(uint(m)) == 1 {
		path = append([][]byte{oldRoot}, path...)
	}

	fn := m - 1
	sn := n - 1

	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}

	fr := path[0]
	sr := path[0]

	for _, c := range path[1:] {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			fr = hasher.HashChildren(c, fr)
			sr = hasher.HashChildren(c, sr)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = hasher.HashChildren(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}

	return sn == 0 && bytes.Equal(fr, oldRoot) && bytes.Equal(sr, newRoot)
}
