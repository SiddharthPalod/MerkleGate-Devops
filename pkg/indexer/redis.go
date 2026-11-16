package indexer

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/redis/go-redis/v9"
)

type EventMetadata struct {
	LeafIndex int    `json:"leaf_index"`
	EventHash string `json:"event_hash"`
	EventType string `json:"event_type"` // e.g. "git_commit", "snyk_scan", "pr_approval", "deploy"
	CommitSHA string `json:"commit_sha,omitempty"`
	PRNumber  int    `json:"pr_number,omitempty"`
	Actor     string `json:"actor,omitempty"`
	Timestamp int64  `json:"timestamp"`
	RawJSON   string `json:"raw_json"`
}

type Indexer interface {
	IndexEvent(ctx context.Context, meta EventMetadata) error
	FindByCommit(ctx context.Context, commitSHA string) ([]int, error)
	FindByPR(ctx context.Context, prNumber int) ([]int, error)
	FindByActor(ctx context.Context, actor string) ([]int, error)
	GetLeafMetadata(ctx context.Context, leafIndex int) (*EventMetadata, error)
}

// RedisIndexer implements Indexer backed directly by github.com/redis/go-redis/v9.
type RedisIndexer struct {
	client *redis.Client
}

func NewRedisIndexer(client *redis.Client) *RedisIndexer {
	return &RedisIndexer{client: client}
}

func (r *RedisIndexer) IndexEvent(ctx context.Context, meta EventMetadata) error {
	data, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("failed to marshal event metadata: %w", err)
	}

	pipe := r.client.Pipeline()

	// 1. Store leaf metadata
	leafKey := fmt.Sprintf("meta:leaf:%d", meta.LeafIndex)
	pipe.Set(ctx, leafKey, data, 0)

	// 2. Index commit SHA
	if meta.CommitSHA != "" {
		commitKey := fmt.Sprintf("idx:commit:%s", meta.CommitSHA)
		pipe.SAdd(ctx, commitKey, meta.LeafIndex)
	}

	// 3. Index PR Number
	if meta.PRNumber > 0 {
		prKey := fmt.Sprintf("idx:pr:%d", meta.PRNumber)
		pipe.SAdd(ctx, prKey, meta.LeafIndex)
	}

	// 4. Index Actor
	if meta.Actor != "" {
		actorKey := fmt.Sprintf("idx:actor:%s", meta.Actor)
		pipe.SAdd(ctx, actorKey, meta.LeafIndex)
	}

	_, err = pipe.Exec(ctx)
	return err
}

func (r *RedisIndexer) getIndicesFromSet(ctx context.Context, key string) ([]int, error) {
	members, err := r.client.SMembers(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}

	indices := make([]int, 0, len(members))
	for _, m := range members {
		idx, err := strconv.Atoi(m)
		if err == nil {
			indices = append(indices, idx)
		}
	}
	return indices, nil
}

func (r *RedisIndexer) FindByCommit(ctx context.Context, commitSHA string) ([]int, error) {
	return r.getIndicesFromSet(ctx, fmt.Sprintf("idx:commit:%s", commitSHA))
}

func (r *RedisIndexer) FindByPR(ctx context.Context, prNumber int) ([]int, error) {
	return r.getIndicesFromSet(ctx, fmt.Sprintf("idx:pr:%d", prNumber))
}

func (r *RedisIndexer) FindByActor(ctx context.Context, actor string) ([]int, error) {
	return r.getIndicesFromSet(ctx, fmt.Sprintf("idx:actor:%s", actor))
}

func (r *RedisIndexer) GetLeafMetadata(ctx context.Context, leafIndex int) (*EventMetadata, error) {
	key := fmt.Sprintf("meta:leaf:%d", leafIndex)
	data, err := r.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}

	var meta EventMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}
	return &meta, nil
}
