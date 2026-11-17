package storage

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const (
	TileHeight = 8                  // Standard C2SP tile height
	TileWidth  = 1 << TileHeight    // 256 entries per tile
	HashSize   = 32                 // SHA-256 digest size in bytes
	TileBytes  = TileWidth * HashSize // 8,192 bytes (8KB)
)

// StorageDriver defines low-level file/object operations.
type StorageDriver interface {
	Write(path string, data []byte, readOnly bool) error
	Read(path string) ([]byte, error)
	Exists(path string) bool
}

// FileStorageDriver writes immutable files to a local directory root.
type FileStorageDriver struct {
	rootDir string
	mu      sync.RWMutex
}

func NewFileStorageDriver(rootDir string) (*FileStorageDriver, error) {
	if err := os.MkdirAll(rootDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create storage root directory: %w", err)
	}
	return &FileStorageDriver{rootDir: rootDir}, nil
}

func (fs *FileStorageDriver) fullPath(relPath string) string {
	return filepath.Join(fs.rootDir, relPath)
}

func (fs *FileStorageDriver) Write(relPath string, data []byte, readOnly bool) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	targetPath := fs.fullPath(relPath)
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Atomic write via temporary file
	tmpPath := targetPath + ".tmp"
	perm := os.FileMode(0644)
	if readOnly {
		perm = os.FileMode(0444) // WORM emulation (read-only)
	}

	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return err
	}

	if readOnly {
		_ = os.Chmod(tmpPath, perm)
	}

	return os.Rename(tmpPath, targetPath)
}

func (fs *FileStorageDriver) Read(relPath string) ([]byte, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	targetPath := fs.fullPath(relPath)
	return os.ReadFile(targetPath)
}

func (fs *FileStorageDriver) Exists(relPath string) bool {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	targetPath := fs.fullPath(relPath)
	_, err := os.Stat(targetPath)
	return err == nil
}

// TileCoordinate helpers
func TileIndex(leafIndex int, level int) int {
	return leafIndex / TileWidth
}

func TileOffset(leafIndex int) int {
	return (leafIndex % TileWidth) * HashSize
}

func TilePath(level int, tileIndex int, partialWidth int) string {
	if partialWidth == 0 || partialWidth == TileWidth {
		return filepath.Join("tiles", fmt.Sprintf("%d", level), fmt.Sprintf("%03d.tile", tileIndex))
	}
	return filepath.Join("tiles", fmt.Sprintf("%d", level), fmt.Sprintf("%03d.p", tileIndex), fmt.Sprintf("%d.tile", partialWidth))
}

func ChunkPath(chunkIndex int) string {
	return filepath.Join("chunks", fmt.Sprintf("%03d.bin", chunkIndex))
}

// TileStore coordinates C2SP tile serialization and raw event chunk persistence.
type TileStore struct {
	driver StorageDriver
	mu     sync.RWMutex
}

func NewTileStore(driver StorageDriver) *TileStore {
	return &TileStore{driver: driver}
}

// SaveLeaves stores a contiguous batch of leaves starting at startLeafIndex.
func (ts *TileStore) SaveLeaves(startLeafIndex int, leafHashes [][]byte, rawEvents [][]byte) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if len(leafHashes) == 0 {
		return nil
	}

	// 1. Persist Raw Event Chunks (chunked by TileWidth = 256)
	if len(rawEvents) > 0 {
		cOffset := 0
		for cOffset < len(rawEvents) {
			currentIdx := startLeafIndex + cOffset
			chunkIdx := currentIdx / TileWidth
			posInChunk := currentIdx % TileWidth

			remaining := TileWidth - posInChunk
			toWrite := len(rawEvents) - cOffset
			if toWrite > remaining {
				toWrite = remaining
			}

			var chunkEvents [][]byte
			chunkFile := ChunkPath(chunkIdx)
			if posInChunk > 0 && ts.driver.Exists(chunkFile) {
				if existingData, err := ts.driver.Read(chunkFile); err == nil {
					if existingEvents, err := DeserializeChunk(existingData); err == nil {
						chunkEvents = existingEvents
					}
				}
			}

			chunkEvents = append(chunkEvents, rawEvents[cOffset:cOffset+toWrite]...)
			chunkBytes := serializeChunk(chunkEvents)
			isFullChunk := (len(chunkEvents) == TileWidth)
			if err := ts.driver.Write(chunkFile, chunkBytes, isFullChunk); err != nil {
				return fmt.Errorf("failed to write event chunk: %w", err)
			}

			cOffset += toWrite
		}
	}

	// 2. Persist Level 0 Tile(s)
	total := len(leafHashes)
	offset := 0

	for offset < total {
		currentIndex := startLeafIndex + offset
		tileIdx := currentIndex / TileWidth
		posInTile := currentIndex % TileWidth

		remainingInTile := TileWidth - posInTile
		toWrite := total - offset
		if toWrite > remainingInTile {
			toWrite = remainingInTile
		}

		// Read existing tile bytes if starting mid-tile
		var tileData []byte
		partialPath := TilePath(0, tileIdx, posInTile)
		if posInTile > 0 && ts.driver.Exists(partialPath) {
			existing, err := ts.driver.Read(partialPath)
			if err == nil {
				tileData = existing
			}
		}

		// Append new hashes
		for i := 0; i < toWrite; i++ {
			tileData = append(tileData, leafHashes[offset+i]...)
		}

		finalWidth := posInTile + toWrite
		isFullTile := (finalWidth == TileWidth)

		targetTilePath := TilePath(0, tileIdx, finalWidth)
		if err := ts.driver.Write(targetTilePath, tileData, isFullTile); err != nil {
			return fmt.Errorf("failed to write tile: %w", err)
		}

		offset += toWrite
	}

	return nil
}

// ReadLeafHash reads a single 32-byte leaf hash at the given index in O(1) time without loading the tree.
func (ts *TileStore) ReadLeafHash(leafIndex int, currentTotalLeaves int) ([]byte, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	if leafIndex < 0 || leafIndex >= currentTotalLeaves {
		return nil, errors.New("leaf index out of bounds")
	}

	tileIdx := leafIndex / TileWidth
	offsetInTile := (leafIndex % TileWidth) * HashSize

	// Try reading full tile first
	fullPath := TilePath(0, tileIdx, TileWidth)
	var data []byte
	var err error

	if ts.driver.Exists(fullPath) {
		data, err = ts.driver.Read(fullPath)
	} else {
		// Read partial tile
		partialWidth := currentTotalLeaves % TileWidth
		if partialWidth == 0 {
			partialWidth = TileWidth
		}
		partialPath := TilePath(0, tileIdx, partialWidth)
		data, err = ts.driver.Read(partialPath)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to read tile for leaf %d: %w", leafIndex, err)
	}

	if len(data) < offsetInTile+HashSize {
		return nil, errors.New("tile payload smaller than expected leaf offset")
	}

	hash := make([]byte, HashSize)
	copy(hash, data[offsetInTile:offsetInTile+HashSize])
	return hash, nil
}

// serializeChunk encodes raw events as: [count_uint32] + foreach: [len_uint32][payload]
func serializeChunk(events [][]byte) []byte {
	var buf []byte
	countHeader := make([]byte, 4)
	binary.BigEndian.PutUint32(countHeader, uint32(len(events)))
	buf = append(buf, countHeader...)

	for _, e := range events {
		lenBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lenBuf, uint32(len(e)))
		buf = append(buf, lenBuf...)
		buf = append(buf, e...)
	}
	return buf
}

// DeserializeChunk decodes raw events from a chunk file.
func DeserializeChunk(data []byte) ([][]byte, error) {
	if len(data) < 4 {
		return nil, io.ErrUnexpectedEOF
	}

	count := binary.BigEndian.Uint32(data[:4])
	offset := 4
	events := make([][]byte, 0, count)

	for i := uint32(0); i < count; i++ {
		if offset+4 > len(data) {
			return nil, io.ErrUnexpectedEOF
		}
		itemLen := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4

		if offset+int(itemLen) > len(data) {
			return nil, io.ErrUnexpectedEOF
		}
		item := make([]byte, itemLen)
		copy(item, data[offset:offset+int(itemLen)])
		offset += int(itemLen)

		events = append(events, item)
	}

	return events, nil
}
