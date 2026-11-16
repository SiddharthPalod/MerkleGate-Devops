package batch

import (
	"context"
	"sync"
	"time"

	"merklegate/pkg/merkle"
)

type Option func(*Engine)

func WithMaxBatchSize(size int) Option {
	return func(b *Engine) {
		if size > 0 {
			b.maxBatchSize = size
		}
	}
}

func WithFlushInterval(interval time.Duration) Option {
	return func(b *Engine) {
		if interval > 0 {
			b.flushInterval = interval
		}
	}
}

type Result struct {
	Tree      *merkle.Tree
	EventData [][]byte
	EpochID   uint64
	CreatedAt time.Time
}

type Engine struct {
	hasher        merkle.Hasher
	maxBatchSize  int
	flushInterval time.Duration

	mu      sync.Mutex
	buffer  [][]byte
	epochID uint64
	results chan Result
	input   chan []byte
	stopCh  chan struct{}
	doneCh  chan struct{}
}

func NewEngine(hasher merkle.Hasher, opts ...Option) *Engine {
	b := &Engine{
		hasher:        hasher,
		maxBatchSize:  10000,
		flushInterval: 1 * time.Second,
		buffer:        make([][]byte, 0, 1024),
		results:       make(chan Result, 100),
		input:         make(chan []byte, 1024),
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}
	for _, opt := range opts {
		opt(b)
	}
	return b
}

func (b *Engine) Start(ctx context.Context) {
	go b.run(ctx)
}

func (b *Engine) Ingest(data []byte) bool {
	select {
	case <-b.stopCh:
		return false
	case b.input <- data:
		return true
	}
}

func (b *Engine) Results() <-chan Result {
	return b.results
}

func (b *Engine) Stop() {
	b.mu.Lock()
	select {
	case <-b.stopCh:
		b.mu.Unlock()
		return
	default:
		close(b.stopCh)
	}
	b.mu.Unlock()

	<-b.doneCh
}

func (b *Engine) run(ctx context.Context) {
	defer close(b.doneCh)
	defer close(b.results)

	ticker := time.NewTicker(b.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			b.flush()
			return
		case <-b.stopCh:
			for {
				select {
				case data := <-b.input:
					b.buffer = append(b.buffer, data)
				default:
					b.flush()
					return
				}
			}
		case data := <-b.input:
			b.buffer = append(b.buffer, data)
			if len(b.buffer) >= b.maxBatchSize {
				b.flush()
			}
		case <-ticker.C:
			if len(b.buffer) > 0 {
				b.flush()
			}
		}
	}
}

func (b *Engine) flush() {
	if len(b.buffer) == 0 {
		return
	}

	events := b.buffer
	b.buffer = make([][]byte, 0, cap(events))
	b.epochID++

	tree, err := merkle.NewTree(events, b.hasher)
	if err != nil {
		return
	}

	res := Result{
		Tree:      tree,
		EventData: events,
		EpochID:   b.epochID,
		CreatedAt: time.Now(),
	}

	select {
	case b.results <- res:
	default:
	}
}
