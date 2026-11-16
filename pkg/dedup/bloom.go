package dedup

import (
	"errors"
	"sync"

	bloom "github.com/bits-and-blooms/bloom/v3"
)

type BloomFilter struct {
	mu     sync.RWMutex
	filter *bloom.BloomFilter
	n      uint
	fp     float64
	count  uint64
}

// New creates a new Bloom filter using the bits-and-blooms/bloom/v3 community library.
func New(expectedItems int, fpRate float64) (*BloomFilter, error) {
	if expectedItems <= 0 {
		return nil, errors.New("expectedItems must be greater than 0")
	}
	if fpRate <= 0 || fpRate >= 1 {
		return nil, errors.New("fpRate must be between 0 and 1 (exclusive)")
	}

	filter := bloom.NewWithEstimates(uint(expectedItems), fpRate)
	return &BloomFilter{
		filter: filter,
		n:      uint(expectedItems),
		fp:     fpRate,
	}, nil
}

// Add inserts an item into the Bloom filter. Thread-safe.
func (bf *BloomFilter) Add(item []byte) {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	bf.filter.Add(item)
	bf.count++
}

// Contains checks whether an item is likely in the Bloom filter. Thread-safe.
func (bf *BloomFilter) Contains(item []byte) bool {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	return bf.filter.Test(item)
}

// Reset clears the Bloom filter for epoch rotations. Thread-safe.
func (bf *BloomFilter) Reset() {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	bf.filter.ClearAll()
	bf.count = 0
}

// Count returns the number of items added.
func (bf *BloomFilter) Count() uint64 {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	return bf.count
}

// BitSize returns the number of bits allocated in the underlying bitset.
func (bf *BloomFilter) BitSize() uint64 {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	return uint64(bf.filter.Cap())
}

// HashCount returns the number of hash functions (k).
func (bf *BloomFilter) HashCount() int {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	return int(bf.filter.K())
}
