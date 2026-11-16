package signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type SignedTreeHead struct {
	TreeSize  int    `json:"tree_size"`
	RootHash  string `json:"root_hash"`  // hex-encoded SHA-256 root
	Timestamp int64  `json:"timestamp"`  // unix epoch seconds
	Sequence  uint64 `json:"sequence"`   // incrementing sequence number
	Signature string `json:"signature"`  // hex-encoded Ed25519 signature
	PublicKey string `json:"public_key"` // hex-encoded Ed25519 public key
}

type Signer interface {
	SignTreeHead(treeSize int, rootHash []byte, sequence uint64) (*SignedTreeHead, error)
	VerifyTreeHead(sth *SignedTreeHead) bool
	PublicKey() ed25519.PublicKey
}

type LocalSigner struct {
	privKey ed25519.PrivateKey
	pubKey  ed25519.PublicKey
}

func NewLocalSigner(privKey ed25519.PrivateKey) *LocalSigner {
	pub := privKey.Public().(ed25519.PublicKey)
	return &LocalSigner{
		privKey: privKey,
		pubKey:  pub,
	}
}

func GenerateKeypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func (s *LocalSigner) PublicKey() ed25519.PublicKey {
	return s.pubKey
}

func (s *LocalSigner) SignTreeHead(treeSize int, rootHash []byte, sequence uint64) (*SignedTreeHead, error) {
	if treeSize < 0 {
		return nil, errors.New("treeSize cannot be negative")
	}
	if len(rootHash) == 0 {
		return nil, errors.New("rootHash cannot be empty")
	}

	now := time.Now().Unix()
	digest := CanonicalSTHDigest(treeSize, rootHash, now, sequence)
	sig := ed25519.Sign(s.privKey, digest)

	return &SignedTreeHead{
		TreeSize:  treeSize,
		RootHash:  hex.EncodeToString(rootHash),
		Timestamp: now,
		Sequence:  sequence,
		Signature: hex.EncodeToString(sig),
		PublicKey: hex.EncodeToString(s.pubKey),
	}, nil
}

func (s *LocalSigner) VerifyTreeHead(sth *SignedTreeHead) bool {
	if sth == nil {
		return false
	}

	rootBytes, err := hex.DecodeString(sth.RootHash)
	if err != nil {
		return false
	}

	sigBytes, err := hex.DecodeString(sth.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return false
	}

	pubBytes, err := hex.DecodeString(sth.PublicKey)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return false
	}

	digest := CanonicalSTHDigest(sth.TreeSize, rootBytes, sth.Timestamp, sth.Sequence)
	return ed25519.Verify(pubBytes, digest, sigBytes)
}

// CanonicalSTHDigest computes the deterministic byte serialization of an STH for signing:
// [8 bytes treeSize][32 bytes rootHash][8 bytes timestamp][8 bytes sequence]
func CanonicalSTHDigest(treeSize int, rootHash []byte, timestamp int64, sequence uint64) []byte {
	buf := make([]byte, 8+len(rootHash)+8+8)
	binary.BigEndian.PutUint64(buf[0:8], uint64(treeSize))
	copy(buf[8:8+len(rootHash)], rootHash)
	offset := 8 + len(rootHash)
	binary.BigEndian.PutUint64(buf[offset:offset+8], uint64(timestamp))
	offset += 8
	binary.BigEndian.PutUint64(buf[offset:offset+8], sequence)
	return buf
}

// SavePrivateKey saves an Ed25519 private key with strict 0400 file permissions.
func SavePrivateKey(path string, privKey ed25519.PrivateKey) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return os.WriteFile(path, privKey, 0400)
}

// LoadPrivateKey loads an Ed25519 private key from disk.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key length: expected %d, got %d", ed25519.PrivateKeySize, len(data))
	}
	return ed25519.PrivateKey(data), nil
}
