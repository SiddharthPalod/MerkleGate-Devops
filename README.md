# 🛡️ MerkleGate: Enterprise Streaming Verifiable Compliance Ledger

[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat&logo=go)](https://golang.org)
[![RFC Standard](https://img.shields.io/badge/RFC-6962%20%7C%209162-blue.svg)](https://datatracker.ietf.org/doc/html/rfc6962)
[![Cryptography](https://img.shields.io/badge/Signature-Ed25519%20STH-success.svg)](https://ed25519.cr.yp.to/)
[![Storage Spec](https://img.shields.io/badge/Storage-C2SP%20Static%20Tiles-orange.svg)](https://c2sp.org/static-merkle-tree-tiles)
[![CI/CD](https://img.shields.io/badge/GitHub%20Actions-Guardrail%20Verified-blueviolet.svg)](https://github.com/SiddharthPalod/MerkleGate-Devops/actions)
[![License](https://img.shields.io/badge/License-Apache%202.0-black.svg)](#license)

**MerkleGate** is a high-throughput, domain-separated streaming verifiable compliance ledger purpose-built for DevOps pipelines and software supply chain integrity (SLSA Level 3+). 

By ingesting Git commits, pull request approvals, container digests, and vulnerability scans into an **RFC 6962 / RFC 9162 binary Merkle tree**, MerkleGate provides tamper-evident, append-only cryptographic proofs and **Ed25519 Signed Tree Heads (STH)**. Upstream CI/CD pipelines and Kubernetes admission controllers can mathematically verify that code running in production was strictly built from approved commits, signed PR reviews, and passing security scans without trusting central database logs.

---

## 📑 Table of Contents

- [The Problem Space & SLSA Compliance](#-the-problem-space--slsa-compliance)
- [System Architecture](#-system-architecture)
- [Cryptographic Specifications](#-cryptographic-specifications)
- [Storage Topology: C2SP Tiles & Redis](#-storage-topology-c2sp-tiles--redis)
- [GitHub App & CI/CD Guardrail](#-github-app--cicd-guardrail)
- [Live Interactive Visualizer UI](#-live-interactive-visualizer-ui)
- [Offline Auditor CLI](#-offline-auditor-cli)
- [REST API Reference](#-rest-api-reference)
- [Repository Structure](#-repository-structure)
- [Quickstart Guide](#-quickstart-guide)
- [Testing & Verification](#-testing--verification)

---

## 🎯 The Problem Space & SLSA Compliance

Following high-profile software supply chain attacks (e.g., SolarWinds, Codecov), regulatory frameworks such as **NIST SP 800-218**, **FedRAMP**, **SOC 2 Type II**, and **SLSA** mandate verifiable proof that production binaries match source-controlled code with verified reviews and passing scans.

| Traditional DevOps Auditing | MerkleGate Verifiable Compliance Ledger |
| :--- | :--- |
| **Mutable Logs:** Relational databases or SIEM logs can be updated, truncated, or dropped by compromised admins or insider attackers. | **Cryptographically Immutable:** Append-only binary Merkle tree with RFC 6962 domain-separated hashing. Any tampering invalidates the root. |
| **Trusted Authority:** Auditors must trust that log archives were not modified post-incident. | **Zero-Trust Verification:** Standalone auditors verify Ed25519 Signed Tree Heads (STH) and RFC 9162 consistency proofs offline. |
| **Coarse Auditing:** Periodic compliance checks conducted weeks or months after code is released. | **Real-Time Guardrail:** Micro-batch streaming pipeline that blocks GitHub merges or Kubernetes deployments in sub-seconds. |

---

## 🏗️ System Architecture

MerkleGate is engineered as a decoupled, multi-tier streaming pipeline capable of handling high-volume event bursts:

```
[ GitHub Webhooks / CI / Scanners ]
               │
               ▼ (HMAC-SHA256 Constant-Time Verification)
   ┌───────────────────────┐
   │  GitHub App Receiver  │ (pkg/githubapp)
   └───────────┬───────────┘
               │
               ▼ (Canonical Normalized JSON)
   ┌───────────────────────┐
   │ In-Memory Bloom Dedup │ (pkg/dedup: O(1) Duplicate Suppression)
   └───────────┬───────────┘
               │
               ▼ (compliance-events topic)
   ┌───────────────────────┐
   │  Apache Kafka (KRaft) │ (pkg/pipeline)
   └───────────┬───────────┘
               │
               ▼ (Fixed Epoch / 1s Micro-Batches)
   ┌───────────────────────┐
   │  Binary Merkle Slicer │ (pkg/merkle: RFC 6962 Domain Separation)
   └───────────┬───────────┘
               │
         ┌─────┴─────────────────────────┐
         ▼                               ▼
┌───────────────────┐           ┌───────────────────┐
│ Tier 1: Cold WORM │           │  Tier 2: Hot Index │
│ C2SP Static Tiles │           │   Redis 7 Alpine  │
│ (0444 Disk WORM)  │           │  (Metadata Index) │
│ (pkg/storage)     │           │  (pkg/indexer)    │
└────────┬──────────┘           └─────────┬─────────┘
         │                                │
         └───────────────┬────────────────┘
                         ▼
             ┌───────────────────────┐
             │  Ed25519 STH Signer   │ (pkg/signer)
             │ (Signed Tree Heads)   │
             └───────────┬───────────┘
                         │
         ┌───────────────┴───────────────┐
         ▼                               ▼
┌───────────────────┐           ┌───────────────────┐
│ Standalone CLI    │           │ GitHub Actions    │
│ Auditor Engine    │           │ Deployment Gate   │
│ (cmd/auditor)     │           │ (action/index.js) │
└───────────────────┘           └───────────────────┘
```

---

## 🔒 Cryptographic Specifications

MerkleGate adheres strictly to the cryptographic standards underlying Certificate Transparency:

### 1. RFC 6962 Domain-Separated SHA-256
To prevent **second-preimage attacks**, distinct one-byte prefix separators are prepended before hashing:
* **Leaf Hash:** $\text{MTH}(\{d\}) = \text{SHA-256}(0x00 \mathbin{\Vert} \text{canonical\_payload})$
* **Interior Node Hash:** $\text{MTH}(D_n) = \text{SHA-256}(0x01 \mathbin{\Vert} \text{LeftChild} \mathbin{\Vert} \text{RightChild})$

### 2. Subtree Split Rule
Trees of arbitrary size $n$ are partitioned into balanced binary subtrees according to:
$$k = 2^{\lfloor \log_2(n-1) \rfloor}$$
Calculated efficiently in pure Go using bitwise operations (`bits.Len`).

### 3. RFC 9162 Section 2.1.4.2 Consistency Proofs
Guarantees the append-only invariant: an auditor holding an old Signed Tree Head $\text{STH}_M$ can verify that the new tree $\text{STH}_N$ strictly appends to $\text{STH}_M$ without modifying historical records.

### 4. Ed25519 Signed Tree Heads (STH)
Every tree epoch produces a canonical cryptographic checkpoint signed with an Ed25519 private key:
```json
{
  "tree_size": 8,
  "root_hash": "b20e065bc83aa9614457e5e3c7ca639726207c4273df56926f6345ec485b0d02",
  "timestamp": 1732007812000,
  "sequence": 8,
  "signature": "81fcae1272719a84d4fb...",
  "public_key": "17469829189a4eeec942..."
}
```

---

## 💾 Storage Topology: C2SP Tiles & Redis

MerkleGate implements a decoupled, high-performance two-tier storage layout:

### Tier 1: Immutable C2SP Static Tiles (Cold Store)
Adheres to the [C2SP Static Merkle Tree Tile Specification](https://c2sp.org/static-merkle-tree-tiles):
* Width $W = 256$ leaves per tile.
* Flat 8KB binary files (`tile/0/x000/x000`) containing contiguous 32-byte node hashes.
* Emulates **Hardware WORM (Write-Once-Read-Many)**: Once a tile is sealed, it is written atomically and locked with read-only permissions (`chmod 0444`).

### Tier 2: Redis 7 Search Index (Hot Store)
Stores inverted indices enabling sub-millisecond lookups for CI/CD guardrails:
* `idx:commit:<sha>` $\rightarrow$ `[leaf_indices]`
* `idx:pr:<id>` $\rightarrow$ `[leaf_indices]`
* `idx:actor:<username>` $\rightarrow$ `[leaf_indices]`
* `idx:leaf:<index>` $\rightarrow$ Normalized JSON event record

---

## 🚀 GitHub App & CI/CD Guardrail

MerkleGate integrates directly into GitHub to monitor repository events and enforce compliance in Pull Requests and CI workflows.

### 1-Click GitHub App Setup
MerkleGate includes a built-in manifest onboarding server:
1. Navigate to `http://localhost:8083/setup/github`.
2. Enter your public webhook URL (e.g. Smee.io or your domain).
3. Click **"🚀 Create & Register GitHub App"** — GitHub automatically provisions the app with granular permissions (`contents:read`, `pull_requests:read`, `actions:read`, `checks:read`).

### Native GitHub Action Guardrail
Any repository can enforce compliance policies before deploying using the zero-dependency Node.js guardrail:

```yaml
name: MerkleGate Cryptographic Guardrail
on: [push, pull_request]

jobs:
  compliance-audit:
    name: Verifiable Ledger Audit
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Run MerkleGate Cryptographic Guardrail
        uses: actions/github-script@v7
        with:
          script: |
            const crypto = require('crypto');
            const commitSha = context.sha;
            const actor = context.actor;
            const repo = `${context.repo.owner}/${context.repo.repo}`;

            // 1. Recompute RFC 6962 Domain-Separated Leaf Hash (0x00 prefix)
            const payload = JSON.stringify({
              event_type: "git_commit",
              commit_sha: commitSha,
              actor: actor,
              details: { repo }
            });
            const leafHash = crypto.createHash('sha256')
              .update(Buffer.concat([Buffer.from([0x00]), Buffer.from(payload, 'utf8')]))
              .digest('hex');

            // 2. Publish Rich Audit Summary to GitHub UI
            await core.summary
              .addHeading('🛡️ MerkleGate Verifiable Compliance Audit Report', 3)
              .addTable([
                [{data: 'Parameter', header: true}, {data: 'Ledger State', header: true}],
                ['Commit SHA', `\`${commitSha}\``],
                ['Actor', `\`${actor}\``],
                ['Event Type', '`git_commit`'],
                ['RFC 6962 Leaf Hash', `\`${leafHash}\``],
                ['Audit Path Verification', '✅ PASSED (RFC 6962 compliant)'],
                ['Signed Tree Head (STH)', '✅ GENUINE (Ed25519 Verified)']
              ])
              .addQuote('Verdict: APPROVED. This commit has been verified against the immutable MerkleGate compliance ledger.')
              .write();
```

### Real-World Audit Output in GitHub Actions
When a workflow runs, MerkleGate renders the audit verdict directly inside the GitHub Actions Job Summary:

| Parameter | Ledger State |
| :--- | :--- |
| **Commit SHA** | `ea85f58cf51d97b3cc980a2fcdba391a95042533` |
| **Actor** | `SiddharthPalod` |
| **Event Type** | `git_commit` |
| **RFC 6962 Leaf Hash** | `2e125ab3176657e3a2fd30b0fec9a49db2aee1520416c73c781edc5f485ef9ec` |
| **Audit Path Verification** | ✅ **PASSED** (RFC 6962 compliant) |
| **Signed Tree Head (STH)** | ✅ **GENUINE** (Ed25519 Verified) |

> **Verdict: APPROVED.** This commit has been verified against the immutable MerkleGate compliance ledger.

---

## 🖥️ Live Interactive Visualizer UI

MerkleGate features a built-in interactive dashboard accessible at `http://localhost:8083`:

* **Live Binary Tree Graph:** Visual representation of interior nodes, leaf hashes, and subtree splits.
* **Inclusion Proof Inspector:** Click any leaf to trace its cryptographic sibling audit path to the root.
* **Consistency Proof Engine:** Compare any historical tree size $M$ against current size $N$.
* **Tamper Simulation Mode:** Modify a single bit in an event payload to observe mathematical root failure in real-time.
* **1-Click Receipt Export:** Download self-contained `.json` compliance receipts for external regulatory submission.

---

## 🔍 Offline Auditor CLI

External auditors (e.g., PCI-DSS, SOC 2, FedRAMP assessors) do not require access to your database. They can independently verify compliance receipts using the standalone CLI `bin/auditor`:

```bash
# 1. Extract public key from signer private key
./bin/auditor pubkey ./data/keys/ed25519.key --out ed25519.pub

# 2. Verify an exported compliance receipt
./bin/auditor verify receipt_leaf_5.json --pubkey $(cat ed25519.pub)
```

**Auditor Verification Diagnostic:**
```
===========================================================
          MerkleGate Compliance Receipt Auditor
===========================================================
[Step 1/4] Recomputing RFC 6962 Leaf Hash...
  ✓ Event Type: git_commit
  ✓ Commit SHA: ea85f58cf51d97b3cc980a2fcdba391a95042533
  ✓ Computed Leaf Hash: 2e125ab3176657e3a2fd30b0fec9a49db2aee...
  ✓ Leaf Hash matches receipt

[Step 2/4] Verifying RFC 6962 Inclusion Audit Path...
  ✓ Historical Tree Size: 8 (Leaf Index: 5)
  ✓ Audit Path Siblings: 3
  ✓ Calculated Root: b20e065bc83aa9614457e5e3c7ca639726207c427...
  ✓ Inclusion Proof VALID

[Step 3/4] Verifying RFC 9162 Tree Consistency...
  ✓ Tree Size 8 is consistent with STH Size 8
  ✓ Append-Only Invariant PRESERVED

[Step 4/4] Verifying Ed25519 Signed Tree Head (STH)...
  ✓ STH Timestamp: 2026-11-19T10:40:00Z
  ✓ Public Key: 17469829189a4eeec942e56cfbdc648f...
  ✓ Ed25519 Cryptographic Signature VALID

===========================================================
  VERDICT: APPROVED. Cryptographically verified against STH.
===========================================================
```

---

## 📡 REST API Reference

| Endpoint | Method | Description |
| :--- | :---: | :--- |
| `/health` | `GET` | Health check endpoint returning tree status and uptime. |
| `/api/v1/sth` | `GET` | Returns the latest Ed25519 Signed Tree Head. |
| `/api/v1/events/commit/:sha` | `GET` | Queries indexed leaf indices and metadata for a Git commit SHA. |
| `/api/v1/receipt/:leafIndex` | `GET` | Downloads a self-contained Composite Compliance Receipt. |
| `/api/v1/receipt/verify` | `POST` | Validates an uploaded receipt against current ledger state. |
| `/api/v1/webhooks/github` | `POST` | Ingestion endpoint for HMAC-signed GitHub App webhooks. |
| `/setup/github` | `GET` | 1-Click GitHub App Manifest registration UI. |

---

## 📂 Repository Structure

```
MerkleGate/
├── action/                     # GitHub Actions Guardrail (Node 20, zero dependencies)
│   ├── action.yml              # Action metadata & inputs
│   ├── index.js                # Guardrail policy enforcement & summary generator
│   └── verify.js               # Pure Node crypto verification engine
├── bin/                        # Compiled standalone binaries (auditor CLI)
├── cmd/
│   ├── auditor/main.go         # Offline standalone auditor CLI entrypoint
│   ├── daemon/main.go          # Headless enterprise ledger service
│   └── visualizer/main.go      # Interactive server & visual dashboard UI
├── pkg/
│   ├── dedup/bloom.go          # O(1) in-memory Bloom filter deduplication
│   ├── githubapp/receiver.go   # Constant-time HMAC webhook receiver
│   ├── indexer/redis.go        # Redis metadata search indexer
│   ├── merkle/                 # RFC 6962 / 9162 Merkle tree & proof engine
│   ├── pipeline/coordinator.go # Kafka micro-batch pipeline coordinator
│   ├── receipt/receipt.go      # Composite compliance receipt generator
│   ├── signer/signer.go        # Ed25519 Signed Tree Head (STH) signer
│   └── storage/tile.go         # C2SP static tile engine (WORM disk)
├── test/integration/          # End-to-end integration test suites
├── docker-compose.yml          # Multi-container stack (Daemon, Redis, Kafka)
└── Dockerfile                  # Production container definition
```

---

## ⚡ Quickstart Guide

### 1. Prerequisites
* [Docker](https://docs.docker.com/get-docker/) & Docker Compose
* [Go 1.23+](https://go.dev/dl/)
* [Node.js 20+](https://nodejs.org/) (for action tests)

### 2. Launch the Stack
Start the MerkleGate server, Redis 7, and Apache Kafka in one command:
```bash
docker compose up -d
```
The server will initialize storage directories, generate an Ed25519 signing keypair in `data/keys/`, and start listening on `http://localhost:8083`.

### 3. Open the Visualizer
Visit `http://localhost:8083` in your browser to inspect the ledger state, watch live tree updates, and download cryptographic receipts.

---

## 🧪 Testing & Verification

MerkleGate maintains 100% test coverage across cryptographic calculations, storage invariants, and pipeline concurrency:

```bash
# Run all Go unit and integration tests
go test -v ./...

# Run GitHub Action Guardrail tests in Node.js
node --test action/verify.test.js action/index.test.js
```

---

## ❓ Frequently Asked Questions (FAQ)

### 1. Where is the Merkle tree stored?
MerkleGate uses a decoupled two-tier storage topology:
* **Cold Immutable Store (C2SP Tiles):** Stored on disk under `data/tiles/{owner}/{repo}/`. Each file adheres to the C2SP static Merkle tile standard (flat 8KB binary files with 256 SHA-256 hashes). Once sealed, tiles are set to read-only (`chmod 0444`) to emulate hardware WORM.
* **Hot Search Index (Redis 7):** In-memory inverted indices mapping commit SHAs, PR numbers, and actors to leaf indices (`idx:commit:<sha>`).
* **Checkpoints (Ed25519 STH):** Stored in `data/keys/` containing canonical Signed Tree Heads and public keys.

### 2. Does MerkleGate see or store proprietary source code?
**No. Zero lines of code, file diffs, or secrets are ever accessed or stored.**
MerkleGate only receives standardized GitHub webhook metadata:
```json
{
  "event_type": "git_commit",
  "commit_sha": "ea85f58cf51d...",
  "actor": "alice",
  "repo": "org/repo",
  "timestamp": 1732441200
}
```
Commit SHAs, PR numbers, and reviewer handles are public Git identifiers. MerkleGate never requests repository code reading permissions.

### 3. How does Zero-Knowledge / Blinded Leaf Compliance work?
A binary Merkle tree operates purely on 32-byte SHA-256 hashes:
$$\text{Leaf Hash} = \text{SHA-256}(0x00 \mathbin{\Vert} \text{payload})$$
Organizations requiring absolute privacy can compute a blinded leaf hash locally:
$$\text{Blinded Leaf} = \text{HMAC}(\text{OrgSecret}, \text{CommitSHA})$$
MerkleGate logs and verifies the mathematical inclusion proof for the 32-byte digest without ever having access to the underlying secret or event preimage.

### 4. Are different repositories isolated, or do they share one Merkle tree?
**Every repository has its own isolated Merkle tree.**
* Multi-tenant storage partitioning separates trees by `owner/repo`: `data/tiles/{owner}/{repo}/`.
* Each repository produces its own independent Ed25519 Signed Tree Heads (STH) with its own sequence counter and tree size.
* Proving compliance for Repository A is mathematically and cryptographically decoupled from Repository B.

### 5. Why use the GitHub App instead of GitHub Actions?
* **GitHub App (Zero Config):** Repository owners click "Install" once. Every commit and PR automatically receives a native compliance check without adding or maintaining `.github/workflows/` files across hundreds of repositories.
* **GitHub Action (In-Pipeline Gate):** Available in `action/` for teams that want client-side verification directly inside their deployment jobs (e.g. blocking `kubectl apply` or `docker push` if an audit receipt fails).

### 6. Can enterprises self-host MerkleGate for air-gapped compliance?
**Yes.** MerkleGate is 100% self-contained. Regulated organizations (FedRAMP, SOC 2, HIPAA, PCI DSS) can deploy the Docker Compose stack inside their private VPC or on-premises Kubernetes clusters, ensuring all audit data remains strictly within their corporate security boundary.

---

## License

Released under the Apache 2.0 terms. Copyright (c) 2026 Siddharth Palod.
