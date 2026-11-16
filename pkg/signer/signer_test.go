package signer

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

func TestLocalSigner_SignAndVerify(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	signer := NewLocalSigner(priv)
	if !bytes.Equal(signer.PublicKey(), pub) {
		t.Fatal("public key mismatch")
	}

	root := sha256.Sum256([]byte("sample_merkle_root_hash"))
	treeSize := 1024
	sequence := uint64(42)

	sth, err := signer.SignTreeHead(treeSize, root[:], sequence)
	if err != nil {
		t.Fatalf("failed to sign STH: %v", err)
	}

	// 1. Valid STH verifies
	if !signer.VerifyTreeHead(sth) {
		t.Fatal("expected valid STH to verify successfully")
	}

	// 2. Tampered TreeSize fails
	tamperedSTH := *sth
	tamperedSTH.TreeSize = 1025
	if signer.VerifyTreeHead(&tamperedSTH) {
		t.Fatal("tampered TreeSize passed verification")
	}

	// 3. Tampered RootHash fails
	tamperedSTH = *sth
	tamperedSTH.RootHash = "0000000000000000000000000000000000000000000000000000000000000000"
	if signer.VerifyTreeHead(&tamperedSTH) {
		t.Fatal("tampered RootHash passed verification")
	}

	// 4. Tampered Sequence fails
	tamperedSTH = *sth
	tamperedSTH.Sequence = 43
	if signer.VerifyTreeHead(&tamperedSTH) {
		t.Fatal("tampered Sequence passed verification")
	}

	// 5. Tampered Signature fails
	tamperedSTH = *sth
	tamperedSTH.Signature = "00" + sth.Signature[2:]
	if signer.VerifyTreeHead(&tamperedSTH) {
		t.Fatal("tampered Signature passed verification")
	}
}

func TestLocalSigner_KeyFilePersistence(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "merklegate-keys-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	_, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	keyPath := filepath.Join(tempDir, "ed25519.key")
	if err := SavePrivateKey(keyPath, priv); err != nil {
		t.Fatalf("failed to save private key: %v", err)
	}

	loadedPriv, err := LoadPrivateKey(keyPath)
	if err != nil {
		t.Fatalf("failed to load private key: %v", err)
	}

	if !bytes.Equal(priv, loadedPriv) {
		t.Fatal("loaded private key does not match original")
	}

	// Test signing with reloaded key
	signer := NewLocalSigner(loadedPriv)
	dummyRoot := sha256.Sum256([]byte("test"))
	sth, err := signer.SignTreeHead(10, dummyRoot[:], 1)
	if err != nil || !signer.VerifyTreeHead(sth) {
		t.Fatal("failed to sign/verify with reloaded key")
	}
}
