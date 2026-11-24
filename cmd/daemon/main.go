package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"merklegate/pkg/githubapp"
	"merklegate/pkg/indexer"
	"merklegate/pkg/pipeline"
	"merklegate/pkg/receipt"
	"merklegate/pkg/signer"
	"merklegate/pkg/storage"
)

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

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func main() {
	portStr := getEnv("PORT", "8083")
	port, _ := strconv.Atoi(portStr)
	kafkaBrokersStr := getEnv("KAFKA_BROKERS", "localhost:9092")
	kafkaTopic := getEnv("KAFKA_TOPIC", "compliance-events")
	kafkaGroup := getEnv("KAFKA_GROUP", "merklegate-daemon")
	redisAddr := getEnv("REDIS_ADDR", "localhost:6379")
	dataDir := getEnv("DATA_DIR", "./data")
	keysDir := getEnv("KEYS_DIR", "./keys")
	githubWebhookSecret := getEnv("GITHUB_WEBHOOK_SECRET", "")

	var brokers []string
	if kafkaBrokersStr != "" {
		for _, b := range strings.Split(kafkaBrokersStr, ",") {
			trimmed := strings.TrimSpace(b)
			if trimmed != "" {
				brokers = append(brokers, trimmed)
			}
		}
	}

	// 1. Key Management (Load or Create Ed25519 Signer)
	keyPath := filepath.Join(keysDir, "ed25519.key")
	privKey, err := signer.LoadPrivateKey(keyPath)
	if err != nil {
		log.Printf("No existing key found at %s, generating new Ed25519 keypair...", keyPath)
		_, newPriv, genErr := signer.GenerateKeypair()
		if genErr != nil {
			log.Fatalf("failed to generate ed25519 keypair: %v", genErr)
		}
		if saveErr := signer.SavePrivateKey(keyPath, newPriv); saveErr != nil {
			log.Printf("warning: could not persist private key: %v", saveErr)
		}
		privKey = newPriv
	}
	localSigner := signer.NewLocalSigner(privKey)
	log.Printf("Loaded Ed25519 Signer (Public Key: %s)", localSigner.PublicKey())

	// 2. Storage Setup (C2SP Tile Store)
	fileDriver, err := storage.NewFileStorageDriver(dataDir)
	if err != nil {
		log.Fatalf("failed to initialize storage driver: %v", err)
	}
	tileStore := storage.NewTileStore(fileDriver)

	// 3. Redis Indexer Setup
	var redisIdx indexer.Indexer
	rClient := redis.NewClient(&redis.Options{Addr: redisAddr})
	pingCtx, pingCancel := context.WithTimeout(context.Background(), 2*time.Second)
	if err := rClient.Ping(pingCtx).Err(); err != nil {
		log.Printf("Warning: Redis at %s unreachable (%v); indexing will be disabled", redisAddr, err)
	} else {
		redisIdx = indexer.NewRedisIndexer(rClient)
		log.Printf("Connected to Redis indexer at %s", redisAddr)
	}
	pingCancel()

	// 4. Pipeline Coordinator Setup
	cfg := pipeline.Config{
		KafkaBrokers:  brokers,
		KafkaTopic:    kafkaTopic,
		ConsumerGroup: kafkaGroup,
		BatchSize:     1000,
		FlushInterval: 1 * time.Second,
		BloomCapacity: 1000000,
		BloomFPRate:   0.001,
	}

	coord, err := pipeline.NewCoordinator(cfg, tileStore, redisIdx, localSigner)
	if err != nil {
		log.Fatalf("failed to create pipeline coordinator: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	coord.Start(ctx)
	log.Printf("MerkleGate Pipeline Coordinator started. Listening on Kafka topic: %s", kafkaTopic)

	// 5. Kafka Helper Producer for manual / test publication
	var producer *pipeline.Producer
	if len(brokers) > 0 {
		producer = pipeline.NewProducer(brokers, kafkaTopic)
	}

	// 6. HTTP API Server (Querying, Health, & Diagnostics)
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":       "ok",
			"total_leaves": coord.TotalLeaves(),
			"topic":        kafkaTopic,
			"redis_online": redisIdx != nil,
		})
	})

	mux.HandleFunc("/api/v1/sth", func(w http.ResponseWriter, r *http.Request) {
		sth := coord.LatestSTH()
		w.Header().Set("Content-Type", "application/json")
		if sth == nil {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "pending",
				"message": "no tree head signed yet (waiting for first batch)",
			})
			return
		}
		json.NewEncoder(w).Encode(sth)
	})

	mux.HandleFunc("/api/v1/events/commit/", func(w http.ResponseWriter, r *http.Request) {
		if redisIdx == nil {
			http.Error(w, "Redis indexer is offline", http.StatusServiceUnavailable)
			return
		}
		commitSHA := strings.TrimPrefix(r.URL.Path, "/api/v1/events/commit/")
		indices, err := redisIdx.FindByCommit(r.Context(), commitSHA)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"commit_sha": commitSHA,
			"indices":    indices,
		})
	})

	mux.HandleFunc("/api/v1/events/pr/", func(w http.ResponseWriter, r *http.Request) {
		if redisIdx == nil {
			http.Error(w, "Redis indexer is offline", http.StatusServiceUnavailable)
			return
		}
		prStr := strings.TrimPrefix(r.URL.Path, "/api/v1/events/pr/")
		prNum, err := strconv.Atoi(prStr)
		if err != nil {
			http.Error(w, "invalid PR number", http.StatusBadRequest)
			return
		}
		indices, err := redisIdx.FindByPR(r.Context(), prNum)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"pr_number": prNum,
			"indices":   indices,
		})
	})

	mux.HandleFunc("/api/v1/events/leaf/", func(w http.ResponseWriter, r *http.Request) {
		if redisIdx == nil {
			http.Error(w, "Redis indexer is offline", http.StatusServiceUnavailable)
			return
		}
		leafStr := strings.TrimPrefix(r.URL.Path, "/api/v1/events/leaf/")
		leafIdx, err := strconv.Atoi(leafStr)
		if err != nil {
			http.Error(w, "invalid leaf index", http.StatusBadRequest)
			return
		}
		meta, err := redisIdx.GetLeafMetadata(r.Context(), leafIdx)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(meta)
	})

	mux.HandleFunc("/api/v1/publish", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if producer == nil {
			http.Error(w, "Kafka producer not configured", http.StatusServiceUnavailable)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || len(body) == 0 {
			http.Error(w, "invalid or empty payload", http.StatusBadRequest)
			return
		}
		if err := producer.Publish(r.Context(), "webhook", body); err != nil {
			http.Error(w, fmt.Sprintf("failed to publish to kafka: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "published_to_kafka",
		})
	})

	mux.HandleFunc("/api/v1/receipt/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var rcpt receipt.ComplianceReceipt
		if err := json.NewDecoder(r.Body).Decode(&rcpt); err != nil {
			http.Error(w, "invalid receipt: "+err.Error(), http.StatusBadRequest)
			return
		}
		report := receipt.Verify(localSigner.PublicKey(), &rcpt)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(report)
	})

	// 7. GitHub App Webhook Receiver & Manifest Onboarding
	ghClient := initGitHubAppClient()
	ghReceiver := githubapp.NewReceiver(githubapp.Config{
		WebhookSecret: githubWebhookSecret,
		Producer:      producer,
		Client:        ghClient,
	})
	mux.Handle("/api/v1/webhooks/github", ghReceiver)

	mux.HandleFunc("/setup/github", func(w http.ResponseWriter, r *http.Request) {
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

	mux.HandleFunc("/setup/github/callback", func(w http.ResponseWriter, r *http.Request) {
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
			ID      int64  `json:"id"`
			Slug    string `json:"slug"`
			HTMLURL string `json:"html_url"`
			Name    string `json:"name"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&appData); err != nil {
			http.Error(w, "Failed to parse GitHub conversion response: "+err.Error(), http.StatusInternalServerError)
			return
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

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	go func() {
		log.Printf("MerkleGate API Server listening at http://localhost:%d", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutting down MerkleGate daemon...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	_ = server.Shutdown(shutdownCtx)
	coord.Stop()
	if producer != nil {
		_ = producer.Close()
	}
	if rClient != nil {
		_ = rClient.Close()
	}
	log.Println("MerkleGate daemon exited cleanly.")
}
