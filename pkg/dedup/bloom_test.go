package dedup

import (
	"fmt"
	"sync"
	"testing"
)

func TestBloomFilter_NoFalseNegatives(t *testing.T) {
	n := 1000
	bf, err := New(n, 0.01)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	items := make([][]byte, n)
	for i := 0; i < n; i++ {
		items[i] = []byte(fmt.Sprintf("event-hash-payload-%d", i))
		bf.Add(items[i])
	}

	for i := 0; i < n; i++ {
		if !bf.Contains(items[i]) {
			t.Fatalf("false negative detected for item %d (mathematically impossible in valid bloom filter)", i)
		}
	}

	if bf.Count() != uint64(n) {
		t.Fatalf("expected count %d, got %d", n, bf.Count())
	}
}

func TestBloomFilter_EmpiricalFPRate(t *testing.T) {
	n := 5000
	targetFP := 0.02
	bf, err := New(n, targetFP)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Add n items
	for i := 0; i < n; i++ {
		bf.Add([]byte(fmt.Sprintf("inserted-key-%d", i)))
	}

	// Test n non-inserted items
	falsePositives := 0
	trials := 5000
	for i := 0; i < trials; i++ {
		nonInserted := []byte(fmt.Sprintf("non-inserted-probe-%d", i))
		if bf.Contains(nonInserted) {
			falsePositives++
		}
	}

	actualFP := float64(falsePositives) / float64(trials)
	// Allow slight statistical variance (up to 2x target rate)
	if actualFP > targetFP*2.0 {
		t.Fatalf("actual false positive rate %.4f significantly exceeds target %.4f", actualFP, targetFP)
	}
}

func TestBloomFilter_Reset(t *testing.T) {
	bf, err := New(100, 0.01)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	key := []byte("event-commit-1234")
	bf.Add(key)

	if !bf.Contains(key) {
		t.Fatal("expected key to be present before reset")
	}

	bf.Reset()

	if bf.Count() != 0 {
		t.Fatalf("expected count 0 after reset, got %d", bf.Count())
	}
	if bf.Contains(key) {
		t.Fatal("expected key to be absent after reset")
	}
}

func TestBloomFilter_Concurrent(t *testing.T) {
	bf, err := New(10000, 0.01)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	workers := 10
	itemsPerWorker := 500
	var wg sync.WaitGroup

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < itemsPerWorker; i++ {
				item := []byte(fmt.Sprintf("worker-%d-item-%d", workerID, i))
				bf.Add(item)
				if !bf.Contains(item) {
					t.Errorf("expected added item to be found immediately")
				}
			}
		}(w)
	}

	wg.Wait()

	expectedCount := uint64(workers * itemsPerWorker)
	if bf.Count() != expectedCount {
		t.Fatalf("expected total count %d, got %d", expectedCount, bf.Count())
	}
}
