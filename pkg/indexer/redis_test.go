package indexer

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func getTestRedisClient(t *testing.T) *redis.Client {
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}

	client := redis.NewClient(&redis.Options{
		Addr: addr,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		t.Skipf("skipping Redis integration test: Redis not reachable at %s (%v)", addr, err)
	}

	return client
}

func TestRedisIndexer_Integration(t *testing.T) {
	client := getTestRedisClient(t)
	defer client.Close()

	ctx := context.Background()
	idx := NewRedisIndexer(client)

	testPrefix := fmt.Sprintf("test:%d", time.Now().UnixNano())
	commitSHA := testPrefix + "-commit"

	e1 := EventMetadata{
		LeafIndex: 100,
		EventHash: "hash-100",
		EventType: "git_commit",
		CommitSHA: commitSHA,
		Actor:     "alice",
		Timestamp: time.Now().Unix(),
		RawJSON:   `{"commit": "test"}`,
	}

	if err := idx.IndexEvent(ctx, e1); err != nil {
		t.Fatalf("failed to index event: %v", err)
	}

	commits, err := idx.FindByCommit(ctx, commitSHA)
	if err != nil {
		t.Fatalf("FindByCommit failed: %v", err)
	}
	if len(commits) != 1 || commits[0] != 100 {
		t.Fatalf("expected leaf 100, got %v", commits)
	}

	meta, err := idx.GetLeafMetadata(ctx, 100)
	if err != nil || meta == nil {
		t.Fatalf("failed to get leaf metadata: %v", err)
	}
	if meta.CommitSHA != commitSHA {
		t.Fatalf("metadata commit SHA mismatch")
	}
}
