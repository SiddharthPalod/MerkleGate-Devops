package pipeline

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/segmentio/kafka-go"

	"merklegate/pkg/batch"
	"merklegate/pkg/dedup"
	"merklegate/pkg/indexer"
	"merklegate/pkg/merkle"
	"merklegate/pkg/signer"
	"merklegate/pkg/storage"
)

type Config struct {
	KafkaBrokers  []string
	KafkaTopic    string
	ConsumerGroup string
	BatchSize     int
	FlushInterval time.Duration
	BloomCapacity uint
	BloomFPRate   float64
}

type Coordinator struct {
	cfg         Config
	reader      *kafka.Reader
	dedup       *dedup.BloomFilter
	batchEngine *batch.Engine
	tileStore   *storage.TileStore
	indexer     indexer.Indexer
	signer      signer.Signer
	hasher      merkle.Hasher

	mu          sync.RWMutex
	totalLeaves int
	sequence    uint64
	latestSTH   *signer.SignedTreeHead

	pendingMu sync.Mutex
	pending   []kafka.Message

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func NewCoordinator(
	cfg Config,
	tileStore *storage.TileStore,
	idx indexer.Indexer,
	sig signer.Signer,
) (*Coordinator, error) {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 1000
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 1 * time.Second
	}
	if cfg.BloomCapacity == 0 {
		cfg.BloomCapacity = 1000000
	}
	if cfg.BloomFPRate <= 0 {
		cfg.BloomFPRate = 0.001
	}

	hasher := merkle.NewSHA256Hasher()
	bf, err := dedup.New(int(cfg.BloomCapacity), cfg.BloomFPRate)
	if err != nil {
		return nil, err
	}
	engine := batch.NewEngine(
		hasher,
		batch.WithMaxBatchSize(cfg.BatchSize),
		batch.WithFlushInterval(cfg.FlushInterval),
	)

	var reader *kafka.Reader
	if len(cfg.KafkaBrokers) > 0 && cfg.KafkaTopic != "" {
		reader = kafka.NewReader(kafka.ReaderConfig{
			Brokers:        cfg.KafkaBrokers,
			Topic:          cfg.KafkaTopic,
			GroupID:        cfg.ConsumerGroup,
			MinBytes:       1,
			MaxBytes:       10e6,
			CommitInterval: 0, // Manual offset commits after batch flush
		})
	}

	return &Coordinator{
		cfg:         cfg,
		reader:      reader,
		dedup:       bf,
		batchEngine: engine,
		tileStore:   tileStore,
		indexer:     idx,
		signer:      sig,
		hasher:      hasher,
		pending:     make([]kafka.Message, 0, 1024),
	}, nil
}

func (c *Coordinator) Start(ctx context.Context) {
	runCtx, cancel := context.WithCancel(ctx)
	c.cancel = cancel

	c.batchEngine.Start(runCtx)

	c.wg.Add(1)
	go c.runBatchProcessor(runCtx)

	if c.reader != nil {
		c.wg.Add(1)
		go c.runConsumer(runCtx)
	}
}

func (c *Coordinator) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
	c.batchEngine.Stop()
	c.wg.Wait()

	if c.reader != nil {
		_ = c.reader.Close()
	}
}

func (c *Coordinator) LatestSTH() *signer.SignedTreeHead {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.latestSTH
}

func (c *Coordinator) TotalLeaves() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.totalLeaves
}

func (c *Coordinator) IngestDirect(data []byte) (bool, error) {
	if len(data) == 0 {
		return false, errors.New("cannot ingest empty payload")
	}

	leafHash := c.hasher.HashLeaf(data)
	if c.dedup.Contains(leafHash) {
		return false, nil // dropped duplicate
	}

	c.dedup.Add(leafHash)
	ok := c.batchEngine.Ingest(data)
	return ok, nil
}

func (c *Coordinator) runConsumer(ctx context.Context) {
	defer c.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		msg, err := c.reader.FetchMessage(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}

		leafHash := c.hasher.HashLeaf(msg.Value)
		if c.dedup.Contains(leafHash) {
			// Duplicate: commit offset to advance past it, but do not buffer
			_ = c.reader.CommitMessages(ctx, msg)
			continue
		}

		c.dedup.Add(leafHash)

		c.pendingMu.Lock()
		c.pending = append(c.pending, msg)
		c.pendingMu.Unlock()

		c.batchEngine.Ingest(msg.Value)
	}
}

func (c *Coordinator) runBatchProcessor(ctx context.Context) {
	defer c.wg.Done()

	for result := range c.batchEngine.Results() {
		c.processBatch(ctx, result)
	}
}

func (c *Coordinator) processBatch(ctx context.Context, res batch.Result) {
	if len(res.EventData) == 0 || res.Tree == nil || res.Tree.Root == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	startLeafIndex := c.totalLeaves
	batchCount := len(res.EventData)

	leafHashes := make([][]byte, batchCount)
	for i, ev := range res.EventData {
		leafHashes[i] = c.hasher.HashLeaf(ev)
	}

	// 1. Persist C2SP tiles and raw event chunks
	if c.tileStore != nil {
		if err := c.tileStore.SaveLeaves(startLeafIndex, leafHashes, res.EventData); err != nil {
			// Storage error logging; in production this could trigger backpressure
			_ = err
		}
	}

	// 2. Index in Redis
	if c.indexer != nil {
		for i, ev := range res.EventData {
			leafIdx := startLeafIndex + i
			meta := parseEventMetadata(leafIdx, leafHashes[i], ev)
			_ = c.indexer.IndexEvent(ctx, meta)
		}
	}

	// 3. Update tree state
	c.totalLeaves += batchCount
	c.sequence++

	// 4. Ed25519 Sign Tree Head (STH)
	if c.signer != nil {
		sth, err := c.signer.SignTreeHead(c.totalLeaves, res.Tree.Root.Hash, c.sequence)
		if err == nil {
			c.latestSTH = sth
		}
	}

	// 5. Commit Kafka offsets for processed messages
	if c.reader != nil {
		c.pendingMu.Lock()
		if len(c.pending) > 0 {
			toCommit := batchCount
			if toCommit > len(c.pending) {
				toCommit = len(c.pending)
			}
			msgsToCommit := c.pending[:toCommit]
			c.pending = c.pending[toCommit:]
			c.pendingMu.Unlock()

			_ = c.reader.CommitMessages(ctx, msgsToCommit...)
		} else {
			c.pendingMu.Unlock()
		}
	}
}

func parseEventMetadata(leafIndex int, leafHash []byte, raw []byte) indexer.EventMetadata {
	meta := indexer.EventMetadata{
		LeafIndex: leafIndex,
		EventHash: hex.EncodeToString(leafHash),
		Timestamp: time.Now().Unix(),
		RawJSON:   string(raw),
	}

	var parsed struct {
		EventType string `json:"event_type"`
		CommitSHA string `json:"commit_sha"`
		PRNumber  int    `json:"pr_number"`
		Actor     string `json:"actor"`
		Timestamp int64  `json:"timestamp"`
	}

	if err := json.Unmarshal(raw, &parsed); err == nil {
		if parsed.EventType != "" {
			meta.EventType = parsed.EventType
		}
		if parsed.CommitSHA != "" {
			meta.CommitSHA = parsed.CommitSHA
		}
		if parsed.PRNumber > 0 {
			meta.PRNumber = parsed.PRNumber
		}
		if parsed.Actor != "" {
			meta.Actor = parsed.Actor
		}
		if parsed.Timestamp > 0 {
			meta.Timestamp = parsed.Timestamp
		}
	}

	if meta.EventType == "" {
		meta.EventType = "generic_event"
	}

	return meta
}
