package merkle

import (
	"crypto/sha256"
)

const (
	RFC6962LeafHashPrefix byte = 0x00
	RFC6962NodeHashPrefix byte = 0x01
)

type Hasher interface {
	EmptyRoot() []byte
	HashLeaf(data []byte) []byte
	HashChildren(left, right []byte) []byte
	Size() int
}

type SHA256Hasher struct{}

func NewSHA256Hasher() *SHA256Hasher {
	return &SHA256Hasher{}
}

func (h *SHA256Hasher) Size() int {
	return sha256.Size
}

func (h *SHA256Hasher) EmptyRoot() []byte {
	sum := sha256.Sum256(nil)
	out := make([]byte, sha256.Size)
	copy(out, sum[:])
	return out
}

func (h *SHA256Hasher) HashLeaf(data []byte) []byte {
	hasher := sha256.New()
	hasher.Write([]byte{RFC6962LeafHashPrefix})
	hasher.Write(data)
	return hasher.Sum(nil)
}

func (h *SHA256Hasher) HashChildren(left, right []byte) []byte {
	buf := make([]byte, 1+len(left)+len(right))
	buf[0] = RFC6962NodeHashPrefix
	copy(buf[1:], left)
	copy(buf[1+len(left):], right)

	sum := sha256.Sum256(buf)
	out := make([]byte, sha256.Size)
	copy(out, sum[:])
	return out
}
