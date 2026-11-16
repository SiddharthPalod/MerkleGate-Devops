package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"merklegate/pkg/indexer"
	"merklegate/pkg/merkle"
	"merklegate/pkg/pipeline"
	"merklegate/pkg/signer"
	"merklegate/pkg/storage"
)

func TestPipeline_EndToEndIntegration(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "pipeline_integration_*")
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

	// Connect to Redis if running in Docker
	var redisIdx indexer.Indexer
	rClient := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	pingCtx, pingCancel := context.WithTimeout(context.Background(), 1*time.Second)
	if err := rClient.Ping(pingCtx).Err(); err == nil {
		redisIdx = indexer.NewRedisIndexer(rClient)
		// Clean up keys used for test
		_ = rClient.Del(context.Background(), "idx:commit:a1b2c3d4e5f6", "idx:pr:101", "idx:actor:alice", "meta:leaf:0", "meta:leaf:1", "meta:leaf:2", "meta:leaf:3").Err()
	}
	pingCancel()

	cfg := pipeline.Config{
		BatchSize:     10,
		FlushInterval: 100 * time.Millisecond,
		BloomCapacity: 10000,
		BloomFPRate:   0.001,
	}

	coord, err := pipeline.NewCoordinator(cfg, tileStore, redisIdx, sig)
	if err != nil {
		t.Fatalf("failed to create coordinator: %v", err)
	}

	ctx := context.Background()
	coord.Start(ctx)
	defer coord.Stop()

	events := [][]byte{
		[]byte(`{"event_type":"git_commit","commit_sha":"a1b2c3d4e5f6","actor":"alice"}`),
		[]byte(`{"event_type":"snyk_scan","commit_sha":"a1b2c3d4e5f6","actor":"snyk-bot"}`),
		[]byte(`{"event_type":"pr_approval","pr_number":101,"actor":"bob"}`),
		[]byte(`{"event_type":"argocd_sync","commit_sha":"a1b2c3d4e5f6","actor":"argocd"}`),
	}

	for _, e := range events {
		ok, err := coord.IngestDirect(e)
		if err != nil || !ok {
			t.Fatalf("expected event ingestion ok, got ok=%v, err=%v", ok, err)
		}
	}

	// Ingest duplicate event
	duplicateAccepted, err := coord.IngestDirect(events[1])
	if err != nil {
		t.Fatalf("unexpected error on duplicate: %v", err)
	}
	if duplicateAccepted {
		t.Fatal("expected duplicate snyk_scan to be rejected by bloom filter, but got accepted")
	}

	// Wait for batch flush
	time.Sleep(250 * time.Millisecond)

	if coord.TotalLeaves() != 4 {
		t.Fatalf("expected 4 leaves in tree, got %d", coord.TotalLeaves())
	}

	sth := coord.LatestSTH()
	if sth == nil {
		t.Fatal("expected non-nil SignedTreeHead after batch flush")
	}

	if sth.TreeSize != 4 {
		t.Fatalf("expected STH tree size 4, got %d", sth.TreeSize)
	}

	if !sig.VerifyTreeHead(sth) {
		t.Fatal("Ed25519 signature verification on STH failed")
	}

	// Verify C2SP disk read
	hasher := merkle.NewSHA256Hasher()
	expectedHash0 := hasher.HashLeaf(events[0])
	storedHash0, err := tileStore.ReadLeafHash(0, 4)
	if err != nil {
		t.Fatalf("failed to read leaf 0 from C2SP tile: %v", err)
	}
	if string(expectedHash0) != string(storedHash0) {
		t.Fatal("stored leaf hash does not match expected leaf hash")
	}

	// If Redis is active, verify search indexing
	if redisIdx != nil {
		commitLeaves, err := redisIdx.FindByCommit(ctx, "a1b2c3d4e5f6")
		if err != nil {
			t.Fatalf("failed to query by commit: %v", err)
		}
		if len(commitLeaves) != 3 {
			t.Fatalf("expected 3 events for commit, got %d: %v", len(commitLeaves), commitLeaves)
		}

		prLeaves, err := redisIdx.FindByPR(ctx, 101)
		if err != nil {
			t.Fatalf("failed to query by PR: %v", err)
		}
		if len(prLeaves) != 1 || prLeaves[0] != 2 {
			t.Fatalf("expected PR 101 at leaf index 2, got %v", prLeaves)
		}

		leaf0Meta, err := redisIdx.GetLeafMetadata(ctx, 0)
		if err != nil {
			t.Fatalf("failed to get leaf 0 metadata: %v", err)
		}
		if leaf0Meta.Actor != "alice" || leaf0Meta.EventType != "git_commit" {
			t.Fatalf("unexpected leaf 0 metadata: %+v", leaf0Meta)
		}
	}
}
