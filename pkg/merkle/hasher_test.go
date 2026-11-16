package merkle

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestSHA256Hasher_DomainSeparation(t *testing.T) {
	hasher := NewSHA256Hasher()

	left := []byte("left_node_data_sample_hash_32b_")
	right := []byte("right_node_data_sample_hash_32b")

	interiorHash := hasher.HashChildren(left, right)
	leafPayload := append(append([]byte(nil), left...), right...)
	leafHash := hasher.HashLeaf(leafPayload)

	if bytes.Equal(interiorHash, leafHash) {
		t.Fatalf("collision detected: leaf hash matches interior node hash")
	}
}

func TestSHA256Hasher_EmptyRoot(t *testing.T) {
	hasher := NewSHA256Hasher()
	expected := sha256.Sum256(nil)

	if !bytes.Equal(hasher.EmptyRoot(), expected[:]) {
		t.Fatalf("EmptyRoot mismatch: got %x, expected %x", hasher.EmptyRoot(), expected)
	}
}

func TestSHA256Hasher_Determinism(t *testing.T) {
	hasher := NewSHA256Hasher()
	data := []byte("audit_compliance_event_payload")

	h1 := hasher.HashLeaf(data)
	h2 := hasher.HashLeaf(data)

	if !bytes.Equal(h1, h2) {
		t.Fatalf("non-deterministic hash across identical inputs")
	}
}
