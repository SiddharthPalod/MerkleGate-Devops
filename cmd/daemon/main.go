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

	"merklegate/pkg/indexer"
	"merklegate/pkg/pipeline"
	"merklegate/pkg/signer"
	"merklegate/pkg/storage"
)

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func main() {
	portStr := getEnv("PORT", "8080")
	port, _ := strconv.Atoi(portStr)
	kafkaBrokersStr := getEnv("KAFKA_BROKERS", "localhost:9092")
	kafkaTopic := getEnv("KAFKA_TOPIC", "compliance-events")
	kafkaGroup := getEnv("KAFKA_GROUP", "merklegate-daemon")
	redisAddr := getEnv("REDIS_ADDR", "localhost:6379")
	dataDir := getEnv("DATA_DIR", "./data")
	keysDir := getEnv("KEYS_DIR", "./keys")

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
