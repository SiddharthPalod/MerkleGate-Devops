package batch

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"merklegate/pkg/merkle"
)

func TestBatchEngine_MaxBatchFlush(t *testing.T) {
	hasher := merkle.NewSHA256Hasher()
	batchSize := 10
	engine := NewEngine(hasher, WithMaxBatchSize(batchSize), WithFlushInterval(10*time.Second))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine.Start(ctx)
	defer engine.Stop()

	for i := 0; i < batchSize; i++ {
		engine.Ingest([]byte(fmt.Sprintf("event-%d", i)))
	}

	select {
	case res := <-engine.Results():
		if len(res.EventData) != batchSize {
			t.Fatalf("expected batch size %d, got %d", batchSize, len(res.EventData))
		}
		if res.Tree == nil || res.Tree.Root == nil {
			t.Fatal("expected non-nil tree and root")
		}
		if res.EpochID != 1 {
			t.Fatalf("expected epoch ID 1, got %d", res.EpochID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for batch flush by size")
	}
}

func TestBatchEngine_TimeIntervalFlush(t *testing.T) {
	hasher := merkle.NewSHA256Hasher()
	engine := NewEngine(hasher, WithMaxBatchSize(100), WithFlushInterval(50*time.Millisecond))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine.Start(ctx)
	defer engine.Stop()

	engine.Ingest([]byte("periodic_event_1"))
	engine.Ingest([]byte("periodic_event_2"))

	select {
	case res := <-engine.Results():
		if len(res.EventData) != 2 {
			t.Fatalf("expected 2 events in periodic batch, got %d", len(res.EventData))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for periodic batch flush")
	}
}

func TestBatchEngine_ConcurrentIngestion(t *testing.T) {
	hasher := merkle.NewSHA256Hasher()
	totalEvents := 1000
	engine := NewEngine(hasher, WithMaxBatchSize(100), WithFlushInterval(100*time.Millisecond))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine.Start(ctx)

	var wg sync.WaitGroup
	workers := 10
	eventsPerWorker := totalEvents / workers

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < eventsPerWorker; i++ {
				engine.Ingest([]byte(fmt.Sprintf("worker-%d-event-%d", workerID, i)))
			}
		}(w)
	}

	wg.Wait()
	engine.Stop()

	received := 0
	for res := range engine.Results() {
		received += len(res.EventData)
	}

	if received != totalEvents {
		t.Fatalf("expected %d total events, got %d", totalEvents, received)
	}
}
