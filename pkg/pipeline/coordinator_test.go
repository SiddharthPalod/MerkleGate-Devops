package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"merklegate/pkg/signer"
	"merklegate/pkg/storage"
)

func TestCoordinator_DirectIngestAndFlush(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "pipeline_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	driver, err := storage.NewFileStorageDriver(tempDir)
	if err != nil {
		t.Fatalf("failed to create storage driver: %v", err)
	}
	tileStore := storage.NewTileStore(driver)

	_, privKey, err := signer.GenerateKeypair()
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}
	sig := signer.NewLocalSigner(privKey)

	cfg := Config{
		BatchSize:     5,
		FlushInterval: 100 * time.Millisecond,
		BloomCapacity: 1000,
		BloomFPRate:   0.01,
	}

	coord, err := NewCoordinator(cfg, tileStore, nil, sig)
	if err != nil {
		t.Fatalf("failed to create coordinator: %v", err)
	}

	ctx := context.Background()
	coord.Start(ctx)
	defer coord.Stop()

	events := [][]byte{
		[]byte(`{"event_type":"git_commit","commit_sha":"a1b2c3d","actor":"alice"}`),
		[]byte(`{"event_type":"snyk_scan","commit_sha":"a1b2c3d","actor":"snyk-bot"}`),
		[]byte(`{"event_type":"pr_approval","pr_number":42,"actor":"bob"}`),
	}

	for _, e := range events {
		ok, err := coord.IngestDirect(e)
		if err != nil || !ok {
			t.Fatalf("expected successful ingestion, got ok=%v, err=%v", ok, err)
		}
	}

	// Ingest a duplicate - should be dropped by bloom filter
	ok, err := coord.IngestDirect(events[0])
	if err != nil {
		t.Fatalf("unexpected error on duplicate: %v", err)
	}
	if ok {
		t.Fatalf("expected duplicate event to be dropped by bloom filter, but got accepted")
	}

	// Wait for batch flush interval
	time.Sleep(250 * time.Millisecond)

	if coord.TotalLeaves() != 3 {
		t.Fatalf("expected 3 leaves, got %d", coord.TotalLeaves())
	}

	sth := coord.LatestSTH()
	if sth == nil {
		t.Fatal("expected non-nil SignedTreeHead after flush")
	}

	if sth.TreeSize != 3 {
		t.Fatalf("expected STH tree size 3, got %d", sth.TreeSize)
	}

	if !sig.VerifyTreeHead(sth) {
		t.Fatal("STH Ed25519 signature verification failed")
	}

	// Verify C2SP tile exists on disk
	tileFile := filepath.Join(tempDir, storage.TilePath(0, 0, 3))
	if _, err := os.Stat(tileFile); os.IsNotExist(err) {
		t.Fatalf("expected partial C2SP tile at %s, but file was not found", tileFile)
	}
}
