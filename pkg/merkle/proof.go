package merkle

import (
	"bytes"
	"errors"
)

type InclusionProof struct {
	LeafIndex int
	TreeSize  int
	AuditPath [][]byte
}

func (t *Tree) GenerateInclusionProof(leafIndex int) (*InclusionProof, error) {
	n := len(t.Leaves)
	if n == 0 {
		return nil, errors.New("cannot generate inclusion proof for empty tree")
	}
	if leafIndex < 0 || leafIndex >= n {
		return nil, errors.New("leaf index out of bounds")
	}

	path := generateAuditPath(leafIndex, n, t.Root)
	return &InclusionProof{
		LeafIndex: leafIndex,
		TreeSize:  n,
		AuditPath: path,
	}, nil
}

func generateAuditPath(m, n int, node *Node) [][]byte {
	if n <= 1 {
		return nil
	}

	k := splitPoint(n)
	if m < k {
		path := generateAuditPath(m, k, node.Left)
		return append(path, node.Right.Hash)
	}

	path := generateAuditPath(m-k, n-k, node.Right)
	return append(path, node.Left.Hash)
}

func VerifyInclusion(hasher Hasher, leafHash, rootHash []byte, proof *InclusionProof) bool {
	if hasher == nil || proof == nil || len(leafHash) == 0 || len(rootHash) == 0 {
		return false
	}
	if proof.TreeSize <= 0 || proof.LeafIndex < 0 || proof.LeafIndex >= proof.TreeSize {
		return false
	}

	calculatedRoot, err := computeRootFromInclusionProof(hasher, proof.LeafIndex, proof.TreeSize, leafHash, proof.AuditPath)
	if err != nil {
		return false
	}

	return bytes.Equal(calculatedRoot, rootHash)
}

func computeRootFromInclusionProof(hasher Hasher, m, n int, leafHash []byte, path [][]byte) ([]byte, error) {
	if n == 1 {
		if len(path) != 0 || m != 0 {
			return nil, errors.New("invalid path for n=1")
		}
		return leafHash, nil
	}

	if len(path) == 0 {
		return nil, errors.New("insufficient path elements")
	}

	k := splitPoint(n)
	sibling := path[len(path)-1]
	remainingPath := path[:len(path)-1]

	if m < k {
		subRoot, err := computeRootFromInclusionProof(hasher, m, k, leafHash, remainingPath)
		if err != nil {
			return nil, err
		}
		return hasher.HashChildren(subRoot, sibling), nil
	}

	subRoot, err := computeRootFromInclusionProof(hasher, m-k, n-k, leafHash, remainingPath)
	if err != nil {
		return nil, err
	}
	return hasher.HashChildren(sibling, subRoot), nil
}
