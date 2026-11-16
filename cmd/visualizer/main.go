package main

import (
	"context"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"merklegate/pkg/dedup"
	"merklegate/pkg/indexer"
	"merklegate/pkg/merkle"
	"merklegate/pkg/signer"
	"merklegate/pkg/storage"
)

//go:embed web/*
var webFS embed.FS

type Server struct {
	mu                 sync.Mutex
	hasher             merkle.Hasher
	events             [][]byte
	originalData       [][]byte
	isTampered         bool
	tree               *merkle.Tree
	signer             *signer.LocalSigner
	latestSTH          *signer.SignedTreeHead
	sequence           uint64
	bloom              *dedup.BloomFilter
	droppedDuplicates  int
	tileStore          *storage.TileStore
	storageDir         string
	redisIdx           indexer.Indexer
}

func NewServer() *Server {
	_, privKey, _ := signer.GenerateKeypair()
	sig := signer.NewLocalSigner(privKey)

	tempDir, err := os.MkdirTemp("", "merklegate_visualizer_*")
	if err != nil {
		log.Fatalf("failed to create temp dir: %v", err)
	}

	driver, _ := storage.NewFileStorageDriver(tempDir)
	store := storage.NewTileStore(driver)

	var redisIdx indexer.Indexer
	rClient := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	pingCtx, pingCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	if err := rClient.Ping(pingCtx).Err(); err == nil {
		redisIdx = indexer.NewRedisIndexer(rClient)
		log.Println("Visualizer connected to live Redis indexer on localhost:6379")
	}
	pingCancel()

	s := &Server{
		hasher:     merkle.NewSHA256Hasher(),
		signer:     sig,
		tileStore:  store,
		storageDir: tempDir,
		redisIdx:   redisIdx,
	}
	s.reset()
	return s
}

func (s *Server) reset() {
	s.events = [][]byte{
		[]byte(`{"event_type":"git_commit","commit_sha":"a7f43b1","actor":"alice"}`),
		[]byte(`{"event_type":"snyk_scan","commit_sha":"a7f43b1","actor":"snyk-bot"}`),
		[]byte(`{"event_type":"pr_approval","pr_number":42,"actor":"bob"}`),
		[]byte(`{"event_type":"argocd_sync","commit_sha":"a7f43b1","actor":"argocd"}`),
	}
	s.originalData = make([][]byte, len(s.events))
	for i, ev := range s.events {
		s.originalData[i] = append([]byte(nil), ev...)
	}
	s.isTampered = false
	s.droppedDuplicates = 0
	s.sequence = 0

	s.bloom, _ = dedup.New(1000, 0.001)

	s.rebuildTree()
}

func (s *Server) rebuildTree() {
	tree, err := merkle.NewTree(s.events, s.hasher)
	if err != nil {
		log.Printf("error building tree: %v", err)
		return
	}
	s.tree = tree

	// Persist C2SP tiles
	leafHashes := make([][]byte, len(s.events))
	for i, e := range s.events {
		leafHashes[i] = s.hasher.HashLeaf(e)
		s.bloom.Add(leafHashes[i])
	}
	_ = s.tileStore.SaveLeaves(0, leafHashes, s.events)

	// Index in Redis
	if s.redisIdx != nil {
		ctx := context.Background()
		for i, e := range s.events {
			meta := parseEventMeta(i, leafHashes[i], e)
			_ = s.redisIdx.IndexEvent(ctx, meta)
		}
	}

	// Sign STH
	if !s.isTampered && s.tree.Root != nil {
		s.sequence++
		sth, err := s.signer.SignTreeHead(len(s.events), s.tree.Root.Hash, s.sequence)
		if err == nil {
			s.latestSTH = sth
		}
	}
}

func parseEventMeta(index int, hash []byte, raw []byte) indexer.EventMetadata {
	meta := indexer.EventMetadata{
		LeafIndex: index,
		EventHash: hex.EncodeToString(hash),
		Timestamp: time.Now().Unix(),
		RawJSON:   string(raw),
	}
	var parsed struct {
		EventType string `json:"event_type"`
		CommitSHA string `json:"commit_sha"`
		PRNumber  int    `json:"pr_number"`
		Actor     string `json:"actor"`
	}
	if err := json.Unmarshal(raw, &parsed); err == nil {
		meta.EventType = parsed.EventType
		meta.CommitSHA = parsed.CommitSHA
		meta.PRNumber = parsed.PRNumber
		meta.Actor = parsed.Actor
	}
	return meta
}

type NodeDTO struct {
	ID     string   `json:"id"`
	Hash   string   `json:"hash"`
	IsLeaf bool     `json:"isLeaf"`
	Index  int      `json:"index,omitempty"`
	Data   string   `json:"data,omitempty"`
	Left   *NodeDTO `json:"left,omitempty"`
	Right  *NodeDTO `json:"right,omitempty"`
}

func serializeNode(n *merkle.Node, leaves []*merkle.Node, events [][]byte) *NodeDTO {
	if n == nil {
		return nil
	}

	dto := &NodeDTO{
		ID:   fmt.Sprintf("%p", n),
		Hash: hex.EncodeToString(n.Hash),
	}

	for i, l := range leaves {
		if l == n {
			dto.IsLeaf = true
			dto.Index = i
			if i < len(events) {
				dto.Data = string(events[i])
			}
			return dto
		}
	}

	dto.IsLeaf = false
	dto.Left = serializeNode(n.Left, leaves, events)
	dto.Right = serializeNode(n.Right, leaves, events)
	return dto
}

func (s *Server) handleGetTree(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var rootDTO *NodeDTO
	if s.tree != nil && s.tree.Root != nil {
		rootDTO = serializeNode(s.tree.Root, s.tree.Leaves, s.events)
	}

	sthValid := false
	if s.latestSTH != nil {
		sthValid = s.signer.VerifyTreeHead(s.latestSTH) && !s.isTampered
	}

	resp := map[string]interface{}{
		"size":              len(s.events),
		"isTampered":        s.isTampered,
		"rootHash":          hex.EncodeToString(s.tree.Root.Hash),
		"root":              rootDTO,
		"droppedDuplicates": s.droppedDuplicates,
		"sth":               s.latestSTH,
		"sthValid":          sthValid,
		"redisOnline":       s.redisIdx != nil,
		"c2spTile":          storage.TilePath(0, 0, len(s.events)),
		"events": func() []string {
			var list []string
			for _, e := range s.events {
				list = append(list, string(e))
			}
			return list
		}(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleAddEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Event string `json:"event"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Event == "" {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	data := []byte(req.Event)
	leafHash := s.hasher.HashLeaf(data)

	// Ingestion Bloom Filter check
	if s.bloom.Contains(leafHash) {
		s.droppedDuplicates++
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":            "duplicate_dropped",
			"message":           "Duplicate event intercepted and dropped by Bloom filter",
			"droppedDuplicates": s.droppedDuplicates,
		})
		return
	}

	s.events = append(s.events, data)
	s.originalData = append(s.originalData, data)
	s.rebuildTree()
	s.mu.Unlock()

	s.handleGetTree(w, r)
}

func (s *Server) handleReset(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.reset()
	s.mu.Unlock()

	s.handleGetTree(w, r)
}

func (s *Server) handleTamper(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if len(s.events) > 0 {
		s.events[0] = []byte(string(s.originalData[0]) + " [TAMPERED_BY_ATTACKER]")
		s.isTampered = true
		// Rebuild tree without resigning STH - STH signature will not match tampered root!
		tree, _ := merkle.NewTree(s.events, s.hasher)
		s.tree = tree
	}
	s.mu.Unlock()

	s.handleGetTree(w, r)
}

func (s *Server) handleInclusionProof(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idxStr := r.URL.Query().Get("leafIndex")
	leafIdx, err := strconv.Atoi(idxStr)
	if err != nil || leafIdx < 0 || leafIdx >= len(s.events) {
		http.Error(w, "invalid leafIndex", http.StatusBadRequest)
		return
	}

	proof, err := s.tree.GenerateInclusionProof(leafIdx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	leafHash := s.hasher.HashLeaf(s.events[leafIdx])
	verified := merkle.VerifyInclusion(s.hasher, leafHash, s.tree.Root.Hash, proof)

	var pathHex []string
	for _, p := range proof.AuditPath {
		pathHex = append(pathHex, hex.EncodeToString(p))
	}

	resp := map[string]interface{}{
		"leafIndex":  leafIdx,
		"treeSize":   proof.TreeSize,
		"auditPath":  pathHex,
		"leafHash":   hex.EncodeToString(leafHash),
		"rootHash":   hex.EncodeToString(s.tree.Root.Hash),
		"verified":   verified && !s.isTampered,
		"isTampered": s.isTampered,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleConsistencyProof(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	mStr := r.URL.Query().Get("oldSize")
	m, err := strconv.Atoi(mStr)
	if err != nil || m <= 0 || m > len(s.events) {
		http.Error(w, "invalid oldSize", http.StatusBadRequest)
		return
	}

	oldTree, err := merkle.NewTree(s.originalData[:m], s.hasher)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	proof, err := s.tree.GenerateConsistencyProof(m)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	verified := merkle.VerifyConsistency(s.hasher, oldTree.Root.Hash, s.tree.Root.Hash, proof)

	var pathHex []string
	for _, p := range proof.Path {
		pathHex = append(pathHex, hex.EncodeToString(p))
	}

	resp := map[string]interface{}{
		"oldSize":    m,
		"newSize":    len(s.events),
		"oldRoot":    hex.EncodeToString(oldTree.Root.Hash),
		"newRoot":    hex.EncodeToString(s.tree.Root.Hash),
		"path":       pathHex,
		"verified":   verified && !s.isTampered,
		"isTampered": s.isTampered,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.redisIdx == nil {
		http.Error(w, "Redis indexer is offline", http.StatusServiceUnavailable)
		return
	}

	query := r.URL.Query().Get("q")
	kind := r.URL.Query().Get("type")

	var indices []int
	var err error

	switch kind {
	case "commit":
		indices, err = s.redisIdx.FindByCommit(r.Context(), query)
	case "pr":
		num, _ := strconv.Atoi(query)
		indices, err = s.redisIdx.FindByPR(r.Context(), num)
	case "actor":
		indices, err = s.redisIdx.FindByActor(r.Context(), query)
	default:
		indices, err = s.redisIdx.FindByCommit(r.Context(), query)
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"query":   query,
		"type":    kind,
		"indices": indices,
	})
}

func main() {
	server := NewServer()

	http.HandleFunc("/api/tree", server.handleGetTree)
	http.HandleFunc("/api/events", server.handleAddEvent)
	http.HandleFunc("/api/reset", server.handleReset)
	http.HandleFunc("/api/tamper", server.handleTamper)
	http.HandleFunc("/api/proof/inclusion", server.handleInclusionProof)
	http.HandleFunc("/api/proof/consistency", server.handleConsistencyProof)
	http.HandleFunc("/api/search", server.handleSearch)

	subFS, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatalf("failed to create sub filesystem: %v", err)
	}
	http.Handle("/", http.FileServer(http.FS(subFS)))

	port := 8083
	log.Printf("MerkleGate Visualizer connected to Go Cryptographic & Ingestion Engine at http://localhost:%d", port)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
