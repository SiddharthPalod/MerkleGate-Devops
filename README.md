# 🛡️ MerkleGate
Enterprise Multi-Tenant Verifiable Compliance Ledger
[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat&logo=go)](https://golang.org)
[![RFC Standard](https://img.shields.io/badge/RFC-6962%20%7C%209162-blue.svg)](https://datatracker.ietf.org/doc/html/rfc6962)
[![Cryptography](https://img.shields.io/badge/Signature-Ed25519%20STH-success.svg)](https://ed25519.cr.yp.to/)
[![Storage Spec](https://img.shields.io/badge/Storage-C2SP%20Static%20Tiles-orange.svg)](https://c2sp.org/static-merkle-tree-tiles)
[![GitHub App](https://img.shields.io/badge/GitHub%20App-Native%20Checks-blueviolet.svg)](https://github.com/settings/apps)
[![License](https://img.shields.io/badge/License-Apache%202.0-black.svg)](#license)

**MerkleGate** is a multi-tenant, domain-separated streaming verifiable compliance ledger purpose-built for DevOps pipelines and software supply chain integrity (SLSA Level 3+). 

Operating as a **native 1-click GitHub App**, MerkleGate automatically ingests Git commits, pull request approvals, and security scans via signed webhooks. It organizes them into **isolated, per-repository binary Merkle trees** (RFC 6962 / RFC 9162) and signs them with **Ed25519 Signed Tree Heads (STH)**. 

Upstream repositories require **zero workflow YAML files**. MerkleGate automatically validates policies and reports cryptographic compliance badges directly into GitHub Pull Requests using the native GitHub Checks API.

---

## 📑 Table of Contents

- [The Problem Space & SLSA Compliance](#-the-problem-space--slsa-compliance)
- [How It Works: Zero-Config Developer Experience](#-how-it-works-zero-config-developer-experience)
- [System Architecture](#-system-architecture)
- [Multi-Tenant Per-Repository Isolation](#-multi-tenant-per-repository-isolation)
- [Cryptographic Specifications](#-cryptographic-specifications)
- [Storage Topology: C2SP Tiles & Redis](#-storage-topology-c2sp-tiles--redis)
- [Live Interactive Visualizer UI](#-live-interactive-visualizer-ui)
- [Offline Auditor CLI](#-offline-auditor-cli)
- [REST API Reference](#-rest-api-reference)
- [Quickstart Guide](#-quickstart-guide)
- [Frequently Asked Questions (FAQ)](#-frequently-asked-questions-faq)
- [License](#license)

---

## 🎯 The Problem Space & SLSA Compliance

Following software supply chain hacks (e.g., SolarWinds, Codecov), regulatory frameworks such as **NIST SP 800-218**, **FedRAMP**, **SOC 2 Type II**, and **SLSA** mandate verifiable proof that production binaries match source-controlled code with approved reviews and passing security scans.

| Traditional DevOps Auditing | MerkleGate Verifiable Compliance Ledger |
| :--- | :--- |
| **Mutable Logs:** Relational databases or SIEM logs can be modified or purged by compromised administrators. | **Cryptographically Immutable:** Append-only binary Merkle tree with RFC 6962 domain separation. Any tampering invalidates the tree root. |
| **Trusted Authority:** Auditors must trust that central log archives were not modified post-incident. | **Zero-Trust Verification:** Standalone auditors verify Ed25519 Signed Tree Heads (STH) and consistency proofs completely offline. |
| **High Setup Friction:** Every repository must copy and maintain complex CI workflow scripts. | **1-Click GitHub App:** Zero code changes in user repositories. Automatic PR checks via GitHub Checks API. |
| **Single Shared Log:** Events from different teams are interleaved, complicating compliance segregation. | **Multi-Tenant Isolation:** Every repository gets an independent binary Merkle tree, separate C2SP disk tiles, and dedicated STHs. |

---

## ⚡ How It Works: Zero-Config Developer Experience

Developers and organizations do not need to write or maintain GitHub Actions workflows in their repositories:

1. **1-Click Install:** An organization installs the MerkleGate GitHub App on their repositories.
2. **Push or PR:** A developer pushes code or opens a Pull Request.
3. **Automatic Auditing:**
   * GitHub sends an HMAC-signed webhook to MerkleGate.
   * MerkleGate hashes the commit metadata into that repository's isolated Merkle tree.
   * MerkleGate signs a new Ed25519 STH checkpoint.
   * MerkleGate calls the GitHub Checks API to post the verified audit badge directly on the PR.

```
──────────────────────────────────────────────────────────────────
  🛡️ MerkleGate / Compliance Ledger
  Status: Completed | Conclusion: Success
  
  ### RFC 6962 & Ed25519 Cryptographic Verification
  Commit `f368fc5...` has been permanently recorded in the ledger.
  
  • Leaf Hash:     ✅ Computed & Verified (0x00 domain separator)
  • Merkle Tree:   ✅ Repositories/SiddharthPalod_MerkleGate-Devops
  • STH Signature: ✅ GENUINE (Ed25519 Verified)
  
  Verdict: APPROVED (SLSA Level 3+ Compliant)
──────────────────────────────────────────────────────────────────
```

---

## 🏗️ System Architecture

MerkleGate is engineered as a decoupled streaming pipeline with inbound webhook verification and outbound check reporting:

```
[ Developer pushes to GitHub ]
               │
               ▼ (Webhook: push, pull_request, workflow_run)
   ┌───────────────────────┐
   │  GitHub App Receiver  │ Constant-time HMAC-SHA256 signature verification
   └───────────┬───────────┘
               │
               ▼ (Canonical Event JSON)
   ┌───────────────────────┐
   │ In-Memory Bloom Dedup │ O(1) duplicate webhook suppression
   └───────────┬───────────┘
               │
               ▼ (compliance-events)
   ┌───────────────────────┐
   │ Apache Kafka / Queue  │ Micro-batch streaming buffer
   └───────────┬───────────┘
               │
               ▼ (Routes by owner/repo)
   ┌───────────────────────────────────────────────────────────┐
   │         Multi-Tenant Merkle Tree Slicing Engine           │
   │  ┌───────────────────────┐     ┌───────────────────────┐  │
   │  │ Repo A: Isolated Tree │     │ Repo B: Isolated Tree │  │
   │  └───────────┬───────────┘     └───────────┬───────────┘  │
   └──────────────┼─────────────────────────────┼──────────────┘
                  │                             │
         ┌────────┴─────────────────────────────┴────────┐
         ▼                                               ▼
┌─────────────────────────────────┐             ┌─────────────────────────────┐
│ Tier 1: Cold WORM Storage       │             │ Tier 2: Hot Search Index    │
│ C2SP Static Disk Tiles (8KB)    │             │ Redis 7 Alpine Inverted Idx │
│ data/repos/{owner}_{repo}/tiles/│             │ idx:commit:{sha} -> leaf    │
└────────────────┬────────────────┘             └──────────────┬──────────────┘
                 │                                             │
                 └──────────────────────┬──────────────────────┘
                                        ▼
                         ┌─────────────────────────────┐
                         │    Ed25519 Checkpoint STH   │
                         │    Signs (Size, Root, Seq)  │
                         └──────────────┬──────────────┘
                                        │
                                        ▼
                         ┌─────────────────────────────┐
                         │   Outbound GitHub Client    │
                         │ Signs RS256 App JWT         │
                         │ Obtains Installation Token  │
                         │ Calls POST /check-runs      │
                         └──────────────┬──────────────┘
                                        │
                                        ▼
                       [ GitHub Pull Request Check: ✅ PASSED ]
```

---

## 🏢 Multi-Tenant Per-Repository Isolation

MerkleGate enforces strict boundary separation across different repositories and organizations:

```
data/repos/
├── demo_default/
│   └── tiles/
├── ACME-Corp_Payment-Service/
│   └── tiles/
└── SiddharthPalod_MerkleGate-Devops/
    └── tiles/
        └── tiles/0/000.p/
            ├── 1.tile
            ├── 2.tile
            └── ... (Live C2SP 8KB Merkle tiles)
```

1. **Storage Path Partitioning:** Each repository stores its C2SP tiles in an independent filesystem or object-storage prefix (`data/repos/{owner}_{repo}/tiles/`).
2. **Decoupled Cryptographic Roots:** Tree sizes, leaf indices, and Ed25519 Signed Tree Heads are calculated independently per repository. Commits in Repo A never alter the root hash of Repo B.
3. **Multi-Tenant Dashboard:** The visualizer UI features an active **Repository Selector** dropdown allowing auditors to inspect any repository's unique Merkle tree, inclusion proofs, and checkpoints in real time.

---

## 🔒 Cryptographic Specifications

MerkleGate strictly adheres to RFC 6962 and RFC 9162 Certificate Transparency standards:

### 1. RFC 6962 Domain-Separated SHA-256
To prevent **second-preimage collision attacks**, distinct one-byte prefix separators are prepended before hashing:
* **Leaf Hash:** `LeafHash = SHA-256(0x00 || canonical_payload)`
* **Interior Node Hash:** `NodeHash = SHA-256(0x01 || left_child || right_child)`

### 2. Subtree Split Rule
Trees of arbitrary size n are partitioned into balanced binary subtrees according to:
`k = 2^(floor(log2(n - 1)))`
Computed in pure Go using bitwise operations (`bits.Len`).

### 3. RFC 9162 Append-Only Consistency Proofs
Guarantees the append-only invariant: an auditor holding an old Signed Tree Head `STH_M` can verify that the new tree `STH_N` strictly appends to `STH_M` without modifying historical records.

### 4. Ed25519 Signed Tree Heads (STH)
Every tree epoch produces an immutable cryptographic checkpoint signed by the ledger's private key:
```json
{
  "tree_size": 4,
  "root_hash": "368f223be64332036b1ed74b9ac9aba85ac16440e8731a78739576c633f583cc",
  "timestamp": 1732441200,
  "sequence": 1,
  "signature": "5736562031fef004d88c6d519da62f...",
  "public_key": "c1c90b52ee3c76c918dbba3a047a28..."
}
```

---

## 💾 Storage Topology: C2SP Tiles & Redis

MerkleGate implements a decoupled, high-performance two-tier storage layout:

### Tier 1: Immutable C2SP Static Tiles (Cold Store)
Adheres to the [C2SP Static Merkle Tree Tile Specification](https://c2sp.org/static-merkle-tree-tiles):
* Width `W = 256` leaves per tile.
* Flat 8KB binary files (`tile/0/x000/x000`) containing contiguous 32-byte node hashes.
* Emulates **Hardware WORM (Write-Once-Read-Many)**: Once a tile is sealed, it is locked with read-only permissions (`chmod 0444`).
* Ready for zero-cost Cloudflare R2 / AWS S3 object storage migration.

### Tier 2: Redis 7 Search Index (Hot Store)
Stores inverted indices enabling sub-millisecond lookups for compliance queries:
* `idx:commit:<sha>` → `[leaf_indices]`
* `idx:pr:<id>` → `[leaf_indices]`
* `idx:actor:<username>` → `[leaf_indices]`
* `meta:leaf:<index>` → Normalized JSON event record

---

## 🖥️ Live Interactive Visualizer UI

MerkleGate features a built-in interactive dashboard accessible at `http://localhost:8083`:

* **Multi-Tenant Repository Selector:** Switch between different repositories to inspect isolated trees.
* **Live Binary Tree Graph:** Visual representation of interior nodes, leaf hashes, and subtree splits.
* **Inclusion Proof Inspector:** Click any leaf to trace its cryptographic sibling audit path to the root.
* **Consistency Proof Engine:** Compare any historical tree size M against current size N.
* **Tamper Simulation Mode:** Modify a single bit in an event payload to observe mathematical root failure in real-time.
* **1-Click Receipt Export:** Download self-contained `.json` compliance receipts for external regulatory submission.

---

## 🔍 Offline Auditor CLI

External auditors (PCI DSS, SOC 2, FedRAMP assessors) do not require access to your database. They can independently verify compliance receipts using the standalone CLI `bin/auditor`:

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
  ✓ Commit SHA: f368fc5e6b3bf9a4e2bc47eb89adba80fb780e59
  ✓ Computed Leaf Hash: 2e125ab3176657e3a2fd30b0fec9a49db2aee...
  ✓ Leaf Hash matches receipt

[Step 2/4] Verifying RFC 6962 Inclusion Audit Path...
  ✓ Historical Tree Size: 4 (Leaf Index: 1)
  ✓ Audit Path Siblings: 2
  ✓ Calculated Root: 368f223be64332036b1ed74b9ac9aba85ac16440e...
  ✓ Inclusion Proof VALID

[Step 3/4] Verifying RFC 9162 Tree Consistency...
  ✓ Tree Size 4 is consistent with STH Size 4
  ✓ Append-Only Invariant PRESERVED

[Step 4/4] Verifying Ed25519 Signed Tree Head (STH)...
  ✓ STH Timestamp: 2026-11-24T10:05:00Z
  ✓ Public Key: c1c90b52ee3c76c918dbba3a047a28...
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
| `/api/v1/repos` | `GET` | Lists all active multi-tenant repository logs. |
| `/api/v1/sth?repo=<owner/repo>` | `GET` | Returns the latest Ed25519 Signed Tree Head for a repository. |
| `/api/v1/events/commit/:sha?repo=<owner/repo>` | `GET` | Queries indexed leaf indices and metadata for a Git commit SHA. |
| `/api/v1/receipt/:leafIndex?repo=<owner/repo>` | `GET` | Downloads a self-contained Composite Compliance Receipt. |
| `/api/v1/receipt/verify` | `POST` | Validates an uploaded receipt against current ledger state. |
| `/api/v1/webhooks/github` | `POST` | Ingestion endpoint for HMAC-signed GitHub App webhooks. |
| `/setup/github` | `GET` | 1-Click GitHub App Manifest registration UI. |

---

## ⚡ Quickstart Guide

### 1. Prerequisites
* [Docker](https://docs.docker.com/get-docker/) & Docker Compose
* [Go 1.23+](https://go.dev/dl/)

### 2. Configure Environment
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Add your `GITHUB_APP_ID` and save your GitHub App private key `.pem` in the root directory.

### 3. Launch the Stack
Start the MerkleGate server, Redis 7, and Apache Kafka in one command:
```bash
docker compose up -d
```
The server will initialize storage directories, generate Ed25519 signing keypairs in `data/keys/`, and start listening on `http://localhost:8083`.

### 4. Open the Visualizer
Visit `http://localhost:8083` in your browser to inspect multi-tenant repository trees, trace inclusion paths, and download cryptographic receipts.

---

## ❓ Frequently Asked Questions (FAQ)

### 1. Where is the Merkle tree stored?
MerkleGate uses a decoupled two-tier storage topology:
* **Cold Immutable Store (C2SP Tiles):** Stored on disk under `data/repos/{owner}_{repo}/tiles/`. Each file adheres to the C2SP static Merkle tile standard (flat 8KB binary files with 256 SHA-256 hashes). Once sealed, tiles are set to read-only (`chmod 0444`) to emulate hardware WORM.
* **Hot Search Index (Redis 7):** In-memory inverted indices mapping commit SHAs, PR numbers, and actors to leaf indices (`idx:commit:<sha>`).
* **Checkpoints (Ed25519 STH):** Stored in `data/keys/` containing canonical Signed Tree Heads and public keys.

### 2. Does MerkleGate see or store proprietary source code?
**No. Zero lines of code, file diffs, or secrets are ever accessed or stored.**
MerkleGate only receives standardized GitHub webhook metadata:
```json
{
  "event_type": "git_commit",
  "commit_sha": "f368fc5e6b3bf9a...",
  "actor": "alice",
  "repo": "org/repo",
  "timestamp": 1732441200
}
```
Commit SHAs, PR numbers, and reviewer handles are public Git identifiers. MerkleGate never requests repository code reading permissions.

### 3. How does Zero-Knowledge / Blinded Leaf Compliance work?
A binary Merkle tree operates purely on 32-byte SHA-256 hashes:
`LeafHash = SHA-256(0x00 || payload)`

Organizations requiring absolute privacy can compute a blinded leaf hash locally before ingestion:
`BlindedLeaf = HMAC(OrgSecret, CommitSHA)`

MerkleGate logs and verifies the mathematical inclusion proof for the 32-byte digest without ever having access to the underlying secret or event preimage.

### 4. Are different repositories isolated, or do they share one Merkle tree?
**Every repository has its own isolated Merkle tree.**
* Multi-tenant storage partitioning separates trees by repository: `data/repos/{owner}_{repo}/tiles/`.
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
