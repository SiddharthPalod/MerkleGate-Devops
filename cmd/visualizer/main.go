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
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"merklegate/pkg/dedup"
	"merklegate/pkg/githubapp"
	"merklegate/pkg/indexer"
	"merklegate/pkg/merkle"
	"merklegate/pkg/receipt"
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
	keysDir := os.Getenv("KEYS_DIR")
	var sig *signer.LocalSigner
	if keysDir != "" {
		keyPath := filepath.Join(keysDir, "ed25519.key")
		if priv, err := signer.LoadPrivateKey(keyPath); err == nil {
			sig = signer.NewLocalSigner(priv)
		} else {
			_, newPriv, _ := signer.GenerateKeypair()
			_ = signer.SavePrivateKey(keyPath, newPriv)
			sig = signer.NewLocalSigner(newPriv)
		}
	} else {
		_, privKey, _ := signer.GenerateKeypair()
		sig = signer.NewLocalSigner(privKey)
	}

	storageDir := os.Getenv("DATA_DIR")
	if storageDir == "" {
		var err error
		storageDir, err = os.MkdirTemp("", "merklegate_visualizer_*")
		if err != nil {
			log.Fatalf("failed to create temp dir: %v", err)
		}
	}

	driver, _ := storage.NewFileStorageDriver(storageDir)
	store := storage.NewTileStore(driver)

	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}
	var redisIdx indexer.Indexer
	rClient := redis.NewClient(&redis.Options{Addr: redisAddr})
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
		storageDir: storageDir,
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

	total := len(s.events)
	tileIdx := total / storage.TileWidth
	partialWidth := total % storage.TileWidth
	chunkIdx := tileIdx
	if partialWidth == 0 && total > 0 {
		tileIdx--
		partialWidth = storage.TileWidth
		chunkIdx = tileIdx
	}
	latestTile := storage.TilePath(0, tileIdx, partialWidth)
	latestChunk := storage.ChunkPath(chunkIdx)

	resp := map[string]interface{}{
		"size":              total,
		"isTampered":        s.isTampered,
		"rootHash":          hex.EncodeToString(s.tree.Root.Hash),
		"root":              rootDTO,
		"droppedDuplicates": s.droppedDuplicates,
		"sth":               s.latestSTH,
		"sthValid":          sthValid,
		"redisOnline":       s.redisIdx != nil,
		"c2spTile":          latestTile,
		"c2spChunk":         latestChunk,
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

	query := strings.TrimSpace(r.URL.Query().Get("q"))
	if query == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"indices":       []int{},
			"matchedHashes": []string{},
			"message":       "empty query",
		})
		return
	}

	indexMap := make(map[int]bool)
	var matchedHashes []string

	// 1. Check Redis indexer (Commit, PR, Actor)
	if s.redisIdx != nil {
		if cIndices, err := s.redisIdx.FindByCommit(r.Context(), query); err == nil {
			for _, idx := range cIndices {
				indexMap[idx] = true
			}
		}
		if aIndices, err := s.redisIdx.FindByActor(r.Context(), query); err == nil {
			for _, idx := range aIndices {
				indexMap[idx] = true
			}
		}
		if num, err := strconv.Atoi(query); err == nil {
			if prIndices, err := s.redisIdx.FindByPR(r.Context(), num); err == nil {
				for _, idx := range prIndices {
					indexMap[idx] = true
				}
			}
		}
	}

	// 2. Check SHA-256 Digests (Root, Internal Nodes, Leaves)
	lowerQ := strings.ToLower(query)
	for i, e := range s.events {
		leafHashHex := strings.ToLower(hex.EncodeToString(s.hasher.HashLeaf(e)))
		if strings.HasPrefix(leafHashHex, lowerQ) || strings.Contains(leafHashHex, lowerQ) {
			indexMap[i] = true
			matchedHashes = append(matchedHashes, leafHashHex)
		}
		if strings.Contains(strings.ToLower(string(e)), lowerQ) {
			indexMap[i] = true
		}
	}

	if s.tree != nil && s.tree.Root != nil {
		rootHashHex := strings.ToLower(hex.EncodeToString(s.tree.Root.Hash))
		if strings.HasPrefix(rootHashHex, lowerQ) || strings.Contains(rootHashHex, lowerQ) {
			matchedHashes = append(matchedHashes, rootHashHex)
		}
	}

	var indices []int
	for idx := range indexMap {
		indices = append(indices, idx)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"query":         query,
		"indices":       indices,
		"matchedHashes": matchedHashes,
		"count":         len(indices) + len(matchedHashes),
	})
}

func (s *Server) handleEventsCommit(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	commitSHA := strings.TrimPrefix(r.URL.Path, "/api/v1/events/commit/")
	var indices []int
	indexMap := make(map[int]bool)

	if s.redisIdx != nil {
		if cIndices, err := s.redisIdx.FindByCommit(r.Context(), commitSHA); err == nil {
			for _, idx := range cIndices {
				if idx >= 0 && idx < len(s.events) {
					indexMap[idx] = true
				}
			}
		}
	}

	// Fallback to in-memory event scan
	lowerSHA := strings.ToLower(commitSHA)
	for i, ev := range s.events {
		if strings.Contains(strings.ToLower(string(ev)), lowerSHA) {
			indexMap[i] = true
		}
	}

	for idx := range indexMap {
		indices = append(indices, idx)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"commit_sha":   commitSHA,
		"leaf_indices": indices,
		"count":        len(indices),
	})
}

func (s *Server) handleGetReceipt(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idxStr := r.URL.Query().Get("leafIndex")
	if idxStr == "" {
		idxStr = strings.TrimPrefix(r.URL.Path, "/api/v1/receipt/")
	}
	leafIdx, err := strconv.Atoi(idxStr)
	if err != nil || leafIdx < 0 || leafIdx >= len(s.events) {
		http.Error(w, "invalid leafIndex", http.StatusBadRequest)
		return
	}

	inclProof, err := s.tree.GenerateInclusionProof(leafIdx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rcpt, err := receipt.BuildReceipt(leafIdx, s.events[leafIdx], inclProof, nil, nil, s.latestSTH)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=receipt-leaf-%d.json", leafIdx))
	json.NewEncoder(w).Encode(rcpt)
}

func (s *Server) handleVerifyReceipt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var rcpt receipt.ComplianceReceipt
	if err := json.NewDecoder(r.Body).Decode(&rcpt); err != nil {
		http.Error(w, "invalid receipt json: "+err.Error(), http.StatusBadRequest)
		return
	}

	pubKey := s.signer.PublicKey()
	report := receipt.Verify(pubKey, &rcpt)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(report)
}

type visualizerProducer struct {
	s *Server
}

func (vp *visualizerProducer) Publish(ctx context.Context, key string, event []byte) error {
	vp.s.mu.Lock()
	defer vp.s.mu.Unlock()

	leafHash := vp.s.hasher.HashLeaf(event)
	if vp.s.bloom.Contains(leafHash) {
		vp.s.droppedDuplicates++
		return nil
	}
	vp.s.bloom.Add(leafHash)

	vp.s.events = append(vp.s.events, event)
	vp.s.originalData = append(vp.s.originalData, event)
	vp.s.rebuildTree()
	return nil
}

func loadEnvFile(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			if os.Getenv(k) == "" {
				os.Setenv(k, v)
			}
		}
	}
}

func initGitHubAppClient() *githubapp.Client {
	loadEnvFile(".env")

	var appID int64
	if idStr := os.Getenv("GITHUB_APP_ID"); idStr != "" {
		fmt.Sscanf(strings.TrimSpace(idStr), "%d", &appID)
	}
	if appID == 0 {
		if idStr := os.Getenv("GitHub-APPID"); idStr != "" {
			fmt.Sscanf(strings.TrimSpace(idStr), "%d", &appID)
		}
	}
	if appID == 0 {
		if b, err := os.ReadFile("data/keys/github-app-id.txt"); err == nil {
			fmt.Sscanf(strings.TrimSpace(string(b)), "%d", &appID)
		}
	}

	if appID == 0 {
		log.Printf("[GitHub App] No App ID configured; check runs disabled.")
		return nil
	}

	var pemBytes []byte
	candidates := []string{
		os.Getenv("GITHUB_APP_PRIVATE_KEY_PATH"),
		"merklegate-privatekey.pem",
		"data/keys/github-app.pem",
		"github-app.pem",
	}
	for _, p := range candidates {
		if p == "" {
			continue
		}
		if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
			pemBytes = b
			log.Printf("[GitHub App] Loaded private key from %s", p)
			break
		}
	}

	if len(pemBytes) == 0 {
		if raw := os.Getenv("GITHUB_APP_PRIVATE_KEY"); raw != "" {
			pemBytes = []byte(raw)
		}
	}

	if len(pemBytes) == 0 {
		log.Printf("[GitHub App] App ID %d found but private key .pem not found; check runs disabled.", appID)
		return nil
	}

	client, err := githubapp.NewClient(appID, pemBytes)
	if err != nil {
		log.Printf("[GitHub App] Failed to initialize client: %v", err)
		return nil
	}

	log.Printf("[GitHub App] Outbound Check Runs Client ACTIVE for App ID %d", appID)
	return client
}

func main() {
	server := NewServer()

	// GitHub Webhook Ingestion & Manifest Onboarding
	ghSecret := os.Getenv("GITHUB_WEBHOOK_SECRET")
	ghClient := initGitHubAppClient()
	ghReceiver := githubapp.NewReceiver(githubapp.Config{
		WebhookSecret: ghSecret,
		Producer:      &visualizerProducer{s: server},
		Client:        ghClient,
	})
	http.Handle("/api/v1/webhooks/github", ghReceiver)

	http.HandleFunc("/setup/github", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
  <title>MerkleGate GitHub App 1-Click Setup</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0d1117; color: #c9d1d9; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; padding: 20px; box-sizing: border-box; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 32px; max-width: 640px; width: 100%%; box-shadow: 0 8px 24px rgba(0,0,0,0.5); }
    h1 { color: #58a6ff; font-size: 24px; margin-top: 0; display: flex; align-items: center; gap: 8px; }
    p { line-height: 1.6; color: #8b949e; font-size: 14px; }
    label { display: block; font-size: 12px; font-weight: 600; text-transform: uppercase; color: #8b949e; margin-top: 16px; margin-bottom: 6px; }
    input { width: 100%%; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 10px 12px; color: #c9d1d9; font-size: 14px; box-sizing: border-box; outline: none; }
    input:focus { border-color: #58a6ff; }
    .hint { font-size: 12px; color: #7ee787; margin-top: 6px; display: block; }
    .hint a { color: #58a6ff; text-decoration: underline; }
    .btn { background: #238636; color: white; border: none; padding: 12px 24px; font-size: 16px; font-weight: 600; border-radius: 6px; cursor: pointer; transition: background 0.2s; width: 100%%; margin-top: 24px; }
    .btn:hover { background: #2ea043; }
    .badge { display: inline-block; background: #1f6feb22; border: 1px solid #1f6feb55; color: #58a6ff; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }
  </style>
</head>
<body>
  <div class="card">
    <h1>🛡️ MerkleGate GitHub App Setup</h1>
    <p>Register the MerkleGate GitHub App on GitHub. Once installed on your repos, it streams <strong>pushes</strong>, <strong>PR approvals</strong>, and <strong>security scans</strong> into the verifiable compliance ledger.</p>
    
    <div>
      <label>1. GitHub App Name <span class="badge">Must be unique on GitHub</span></label>
      <input id="appName" value="MerkleGate-Ledger" />
    </div>

    <div>
      <label>2. Public Webhook URL <span class="badge">HTTPS required by GitHub</span></label>
      <input id="webhookUrl" placeholder="https://your-domain.com/api/v1/webhooks/github or https://smee.io/..." />
      <span class="hint">⚡ Testing locally? Get an instant free public proxy at <a href="https://smee.io/new" target="_blank">smee.io/new</a> (no account needed) and paste the URL here.</span>
    </div>

    <form id="manifestForm" action="https://github.com/settings/apps/new" method="post" target="_blank">
      <input type="hidden" name="manifest" id="manifestPayload" value="" />
      <button type="submit" class="btn">🚀 Register GitHub App on GitHub</button>
    </form>
  </div>

  <script>
    // Randomize default name so it doesn't collide on GitHub
    const rand = Math.random().toString(36).substring(2, 6);
    document.getElementById('appName').value = 'MerkleGate-' + rand;

    document.getElementById('manifestForm').addEventListener('submit', function(e) {
      const name = document.getElementById('appName').value.trim() || ('MerkleGate-' + rand);
      let hookUrl = document.getElementById('webhookUrl').value.trim();
      
      if (!hookUrl || !hookUrl.startsWith('https://')) {
        alert('GitHub requires a public HTTPS URL for webhooks.\n\nFor local testing, click the smee.io/new link to get a free instant HTTPS URL, then paste it into the Webhook URL field.');
        e.preventDefault();
        return;
      }

      const manifest = {
        name: name,
        url: "https://github.com/org/merklegate",
        redirect_url: window.location.origin + "/setup/github/callback",
        hook_attributes: {
          url: hookUrl,
          active: true
        },
        description: "Enterprise streaming verifiable compliance ledger for Git commits, PR approvals, and security scans.",
        public: true,
        default_permissions: {
          contents: "read",
          pull_requests: "read",
          actions: "read",
          checks: "write",
          statuses: "write"
        },
        default_events: [
          "push",
          "pull_request",
          "pull_request_review",
          "workflow_run",
          "check_run"
        ]
      };

      document.getElementById('manifestPayload').value = JSON.stringify(manifest);
    });
  </script>
</body>
</html>`)
	})

	http.HandleFunc("/setup/github/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "missing code parameter from GitHub", http.StatusBadRequest)
			return
		}

		convertURL := fmt.Sprintf("https://api.github.com/app-manifests/%s/conversions", code)
		convReq, err := http.NewRequest(http.MethodPost, convertURL, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		convReq.Header.Set("Accept", "application/vnd.github+json")
		convReq.Header.Set("User-Agent", "MerkleGate-Ledger")

		resp, err := http.DefaultClient.Do(convReq)
		if err != nil {
			http.Error(w, "Failed to connect to GitHub API: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		var appData struct {
			ID            int64  `json:"id"`
			Slug          string `json:"slug"`
			HTMLURL       string `json:"html_url"`
			Name          string `json:"name"`
			PEM           string `json:"pem"`
			WebhookSecret string `json:"webhook_secret"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&appData); err != nil {
			http.Error(w, "Failed to parse GitHub conversion response: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if appData.PEM != "" {
			_ = os.MkdirAll("data/keys", 0755)
			_ = os.WriteFile("data/keys/github-app.pem", []byte(appData.PEM), 0600)
			_ = os.WriteFile("data/keys/github-app-id.txt", []byte(fmt.Sprintf("%d", appData.ID)), 0644)
			log.Printf("[GitHub App] Auto-saved private key and App ID %d to data/keys/", appData.ID)
		}

		installURL := fmt.Sprintf("https://github.com/apps/%s/installations/new", appData.Slug)
		if appData.HTMLURL != "" {
			installURL = fmt.Sprintf("%s/installations/new", appData.HTMLURL)
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
  <title>GitHub App Created!</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0d1117; color: #c9d1d9; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 36px; max-width: 550px; text-align: center; }
    h1 { color: #3fb950; font-size: 24px; margin-top: 0; }
    p { color: #8b949e; line-height: 1.6; }
    .btn { display: inline-block; background: #238636; color: white; text-decoration: none; padding: 12px 24px; font-size: 15px; font-weight: 600; border-radius: 6px; margin-top: 20px; }
    .btn:hover { background: #2ea043; }
  </style>
</head>
<body>
  <div class="card">
    <h1>🎉 GitHub App Registered!</h1>
    <p>Your app <strong>%s</strong> (ID: %d) has been permanently created on GitHub.</p>
    <p>Now install it on your repositories to begin streaming compliance events into MerkleGate.</p>
    <a href="%s" class="btn">🚀 Install App on My Repositories</a>
  </div>
</body>
</html>`, appData.Name, appData.ID, installURL)
	})

	http.HandleFunc("/api/tree", server.handleGetTree)
	http.HandleFunc("/api/events", server.handleAddEvent)
	http.HandleFunc("/api/reset", server.handleReset)
	http.HandleFunc("/api/tamper", server.handleTamper)
	http.HandleFunc("/api/proof/inclusion", server.handleInclusionProof)
	http.HandleFunc("/api/proof/consistency", server.handleConsistencyProof)
	http.HandleFunc("/api/search", server.handleSearch)
	http.HandleFunc("/api/v1/events/commit/", server.handleEventsCommit)
	http.HandleFunc("/api/v1/receipt/", server.handleGetReceipt)
	http.HandleFunc("/api/v1/receipt/verify", server.handleVerifyReceipt)

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
