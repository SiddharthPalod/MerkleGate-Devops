**The Problem Space:**
Following the SolarWinds hack, the US government and enterprise sectors mandated strict software supply chain security (like the SLSA framework). Security teams must prove that what is running in production is exactly what was reviewed, scanned, and approved—with no bypassed steps.

**The Niche Implementation:**
Instead of a generic API, you build a ledger purpose-built exclusively for DevOps tooling.

* **Niche Ingestion:** The ledger natively ingests compliance webhooks directly from GitHub, GitLab, Jenkins, Snyk, and ArgoCD.
* **Niche Data Model:** It specifically hashes Git commits, vulnerability scan results, PR approvals, and container SHAs.
* **Niche Verification:** The "Auditor CLI" isn't for human auditors—it is a Kubernetes admission controller. Before a pod spins up, the cluster queries the ledger. If the container cannot provide a Merkle proof showing it passed a security scan and received two human PR approvals, the deployment is hard-blocked.
* **Niche Output:** It automatically generates cryptographic Software Bills of Materials (SBOMs) for enterprise customers, proving exactly how the software was built.

**Why this niche wins:**
It perfectly matches the architecture. CI/CD pipelines generate massive volumes of streaming micro-events (high throughput), the logs are prime targets for attackers trying to hide backdoors (tamper-proof requirement), and regulators actively demand proof of compliance (offline verification).

**High-Throughput Streaming Verifiable Compliance Ledger**.

This plan pairs high-throughput micro-batch ingestion with binary Merkle trees and static C2SP-compliant tile generation, designed to be fully self-contained for local development, GitHub, and Docker.

---

## Phase 1: Core Cryptographic Engine & Merkle Tree Subsystem ✅ [COMPLETED]

**Objective:** Build a deterministic, domain-separated binary Merkle tree engine in **Go** that handles micro-batches of audit events, computes leaf hashes, and generates inclusion and consistency proofs.

* **Domain-Separated Hashing (`pkg/merkle/hasher.go`):** Implemented SHA-256 adhering to RFC 6962 standards, prepending distinct prefix bytes for leaves (`0x00`) and interior nodes (`0x01`) to prevent second-preimage attacks.
* **Binary Merkle Tree Subsystem (`pkg/merkle/tree.go`):** Pointer-based tree construction implementing RFC 6962 subtree split rule $k = 2^{\lfloor \log_2(n-1) \rfloor}$ using bitwise operations (`bits.Len`).
* **Micro-Batch Slicing Engine (`pkg/merkle/batch.go`):** Thread-safe in-memory buffer that groups streaming events into fixed-size epochs (e.g., 10,000 events) or time intervals (e.g., 1s), outputting finalized trees and epoch IDs.
* **Proof Generation Logic:**
  * **Inclusion Proofs (`pkg/merkle/proof.go`):** Generates minimal audit paths and mathematically reconstructs roots dynamically.
  * **Consistency Proofs (`pkg/merkle/consistency.go`):** Generates consistency paths and verifies historical append-only invariants using RFC 9162 Section 2.1.4.2 bit-decomposition algorithm.
* **Testing & Validation:** Property-based tests verifying that single-bit tampering anywhere in an event payload, audit sibling, or root hash fails verification.
* **Live Interactive Visualizer (`cmd/visualizer/`):** Self-contained Go HTTP server with embedded UI displaying real-time tree structure, inclusion audit paths, consistency proofs, and tamper simulation.

---

## Phase 2: Ingestion Pipeline & Decoupled Storage Topology ✅ [COMPLETED]

**Objective:** Engineer a high-throughput ingestion daemon with in-memory deduplication, micro-batch tree generation, and a decoupled two-tier storage topology (local C2SP static disk tiles + Redis search index) with an Ed25519 Signed Tree Head (STH) checkpoint signer, containerized via Docker and Apache Kafka.

* **In-Memory Bloom Filter Deduplication (`pkg/dedup/bloom.go`):**
  * Fast $O(1)$ in-memory Bloom filter wrapping community library `github.com/bits-and-blooms/bloom/v3`.
  * Intercepts incoming event payloads by canonical leaf hash, dropping duplicate webhooks before batch buffering. Verified in `bloom_test.go`.
* **Tier 1: Cold / Immutable Storage — Local C2SP Tile Engine (`pkg/storage/tile.go`):**
  * Free, zero-cost, self-contained storage topology ($W=256$, 8KB tiles) adhering to C2SP static tile specifications.
  * Emulates WORM (Write-Once-Read-Many) by setting file permissions to read-only (`0444`) on atomic rename. Verified in `tile_test.go`.
* **Tier 2: Hot / Search Index Store — Redis Indexer (`pkg/indexer/redis.go`):**
  * Concurrently indexes metadata keys using `github.com/redis/go-redis/v9`:
    * `idx:commit:<sha>` $\rightarrow$ `leaf_index`
    * `idx:pr:<id>` $\rightarrow$ `leaf_index`
    * `idx:actor:<name>` $\rightarrow$ `[leaf_indices]`
    * `idx:leaf:<index>` $\rightarrow$ Event JSON metadata
  * Verified live against running Docker Redis container in `redis_test.go`.
* **Local Ed25519 Checkpoint Signer (`pkg/signer/signer.go`):**
  * Uses Go standard library `crypto/ed25519` for canonical deterministic signing and verification.
  * Generates Signed Tree Heads (STHs) containing `(TreeSize, RootHash, Timestamp, Sequence, Signature, PublicKey)`.
  * Persists private keys with strict `0400` file permissions. Verified in `signer_test.go`.
* **Kafka-Native Pipeline Coordinator (`pkg/pipeline/coordinator.go`):**
  * Orchestrates pure streaming event ingestion using `github.com/segmentio/kafka-go`.
  * Wires Bloom Dedup $\rightarrow$ Micro-Batch Slicing $\rightarrow$ C2SP Tile Store $\rightarrow$ Redis Index $\rightarrow$ STH Signer.
  * Verified in `coordinator_test.go` and full end-to-end integration test `test/integration/pipeline_test.go`.
* **Server Daemon & Docker Compose (`cmd/daemon/main.go`, `docker-compose.yml`):**
  * Multi-container compose running Redis 7 Alpine, Apache Kafka in KRaft mode, and the MerkleGate daemon.
  * Exposes HTTP endpoints for STH querying (`/api/v1/sth`), commit lookups (`/api/v1/events/commit/:sha`), and health checks.
* **Upgraded Live Visualizer (`cmd/visualizer/`):**
  * Upgraded with live Phase 2 topology ribbon: live Ed25519 STH verification badge, C2SP Level-0 tile breakdown, Bloom filter duplicate drop counter, and Redis search index explorer.

---

## Phase 3: Auditor Verification Gateway & Receipt Engine

**Objective:** Expose an external verification API and standalone CLI tool that allows internal security teams and external regulators (PCI DSS, FedRAMP, ISO 27001 auditors) to independently verify log integrity without accessing raw internal databases.

* **Self-Contained "Compliance Receipt" JSON Format:** When an event is queried, output a cryptographic receipt containing:
  1. The raw event payload.
  2. Its computed leaf hash and position index.
  3. The Merkle inclusion audit path.
  4. The latest Signed Tree Head (STH) signed by the organization's root key.
* **Offline Verification CLI / Verifier Tool:** Build a lightweight standalone verifier script that takes a compliance receipt, recalculates the Merkle path hashes locally, compares the derived root against the signed STH, and validates the Ed25519 signature—completely isolated from the server backend.
* **Auditor Dashboard / API Endpoints:** Provide REST endpoints for batch verification, historical tree consistency proof checks, and automated compliance report generation.

---

## Phase 4: Enterprise CI/CD Guardrails & Operational Hardening

**Objective:** Harden the system for deployment, tying the ledger directly into enterprise CI/CD pipelines, container orchestration, and automated incident alerting.

* **GitOps & Pipeline Attestation Hooks:** Integrate the ledger client SDK into deployment pipelines (ArgoCD/GitHub Actions) to automatically log every infrastructure drift waiver, security exception, or policy override as an immutable compliance leaf.
* **Active Tamper Detection & Monitoring:** Deploy a background watcher daemon that continuously fetches published STHs, recalculates consistency proofs across sequential checkpoints, and triggers high-priority security alerts if an append-only invariant violation is detected.
* **Docker & Container Packaging:** Provide a multi-stage `Dockerfile` and `docker-compose.yml` orchestrating the MerkleGate daemon, Redis indexer, and visualizer.
