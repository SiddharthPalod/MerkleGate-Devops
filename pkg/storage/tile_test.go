package storage

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"merklegate/pkg/merkle"
)

func TestTileMath(t *testing.T) {
	cases := []struct {
		leafIndex      int
		expectedTile   int
		expectedOffset int
	}{
		{0, 0, 0},
		{1, 0, 32},
		{255, 0, 255 * 32},
		{256, 1, 0},
		{257, 1, 32},
		{511, 1, 255 * 32},
		{512, 2, 0},
	}

	for _, c := range cases {
		tile := TileIndex(c.leafIndex, 0)
		if tile != c.expectedTile {
			t.Errorf("leaf %d: expected tile %d, got %d", c.leafIndex, c.expectedTile, tile)
		}
		offset := TileOffset(c.leafIndex)
		if offset != c.expectedOffset {
			t.Errorf("leaf %d: expected offset %d, got %d", c.leafIndex, c.expectedOffset, offset)
		}
	}
}

func TestTileStore_PartialAndFullTile(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "merklegate-tiles-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	driver, err := NewFileStorageDriver(tempDir)
	if err != nil {
		t.Fatalf("failed to create driver: %v", err)
	}

	hasher := merkle.NewSHA256Hasher()
	store := NewTileStore(driver)

	// Step 1: Write a partial batch of 100 leaves
	leaves1 := make([][]byte, 100)
	rawEvents1 := make([][]byte, 100)
	for i := 0; i < 100; i++ {
		rawEvents1[i] = []byte(fmt.Sprintf("compliance-event-%d", i))
		leaves1[i] = hasher.HashLeaf(rawEvents1[i])
	}

	if err := store.SaveLeaves(0, leaves1, rawEvents1); err != nil {
		t.Fatalf("failed to save batch 1: %v", err)
	}

	// Verify reading a leaf hash from the partial tile
	h42, err := store.ReadLeafHash(42, 100)
	if err != nil {
		t.Fatalf("failed to read leaf 42: %v", err)
	}
	if !bytes.Equal(h42, leaves1[42]) {
		t.Fatalf("leaf hash mismatch for leaf 42")
	}

	// Step 2: Write next 200 leaves (spans remaining 156 of tile 0, and 44 into tile 1)
	leaves2 := make([][]byte, 200)
	rawEvents2 := make([][]byte, 200)
	for i := 0; i < 200; i++ {
		rawEvents2[i] = []byte(fmt.Sprintf("compliance-event-%d", 100+i))
		leaves2[i] = hasher.HashLeaf(rawEvents2[i])
	}

	if err := store.SaveLeaves(100, leaves2, rawEvents2); err != nil {
		t.Fatalf("failed to save batch 2: %v", err)
	}

	totalLeaves := 300

	// Verify leaf 0 in tile 0
	h0, err := store.ReadLeafHash(0, totalLeaves)
	if err != nil || !bytes.Equal(h0, leaves1[0]) {
		t.Fatalf("leaf 0 mismatch after tile completion")
	}

	// Verify leaf 255 (the last leaf in full tile 0)
	h255, err := store.ReadLeafHash(255, totalLeaves)
	if err != nil || !bytes.Equal(h255, leaves2[155]) {
		t.Fatalf("leaf 255 mismatch in full tile 0")
	}

	// Verify leaf 256 (the first leaf in tile 1)
	h256, err := store.ReadLeafHash(256, totalLeaves)
	if err != nil || !bytes.Equal(h256, leaves2[156]) {
		t.Fatalf("leaf 256 mismatch in tile 1")
	}

	// Verify leaf 299 (the last leaf in partial tile 1)
	h299, err := store.ReadLeafHash(299, totalLeaves)
	if err != nil || !bytes.Equal(h299, leaves2[199]) {
		t.Fatalf("leaf 299 mismatch in partial tile 1")
	}
}

func TestChunkSerialization(t *testing.T) {
	original := [][]byte{
		[]byte("git:commit:abcdef1234"),
		[]byte("snyk:scan:clean"),
		[]byte("pr:approve:alice"),
	}

	encoded := serializeChunk(original)
	decoded, err := DeserializeChunk(encoded)
	if err != nil {
		t.Fatalf("failed to deserialize chunk: %v", err)
	}

	if len(decoded) != len(original) {
		t.Fatalf("expected %d events, got %d", len(original), len(decoded))
	}

	for i := range original {
		if !bytes.Equal(original[i], decoded[i]) {
			t.Fatalf("event %d mismatch: got %s, expected %s", i, decoded[i], original[i])
		}
	}
}
