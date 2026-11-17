package receipt

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"merklegate/pkg/merkle"
	"merklegate/pkg/signer"
)

type InclusionProofDTO struct {
	TreeSize  int      `json:"tree_size"`
	AuditPath []string `json:"audit_path"`
}

type ConsistencyProofDTO struct {
	OldSize int      `json:"old_size"`
	NewSize int      `json:"new_size"`
	Path    []string `json:"path"`
}

type ComplianceReceipt struct {
	Version          string                `json:"version"`
	LeafIndex        int                   `json:"leaf_index"`
	LeafHash         string                `json:"leaf_hash"`
	RawPayload       string                `json:"raw_payload"`
	HistoricalRoot   string                `json:"historical_root,omitempty"`
	InclusionProof   InclusionProofDTO     `json:"inclusion_proof"`
	ConsistencyProof *ConsistencyProofDTO  `json:"consistency_proof,omitempty"`
	SignedTreeHead   signer.SignedTreeHead `json:"signed_tree_head"`
	CreatedAt        int64                 `json:"created_at"`
}

type VerificationStep struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Details string `json:"details"`
}

type VerificationReport struct {
	Valid     bool               `json:"valid"`
	LeafIndex int                `json:"leaf_index"`
	TreeSize  int                `json:"tree_size"`
	Steps     []VerificationStep `json:"steps"`
	Error     string             `json:"error,omitempty"`
}

// BuildReceipt constructs a self-contained compliance receipt from existing components.
func BuildReceipt(
	leafIndex int,
	rawPayload []byte,
	incl *merkle.InclusionProof,
	constProof *merkle.ConsistencyProof,
	historicalRoot []byte,
	sth *signer.SignedTreeHead,
) (*ComplianceReceipt, error) {
	if incl == nil {
		return nil, errors.New("inclusion proof cannot be nil")
	}
	if sth == nil {
		return nil, errors.New("signed tree head cannot be nil")
	}

	hasher := merkle.NewSHA256Hasher()
	leafHash := hasher.HashLeaf(rawPayload)

	auditHex := make([]string, len(incl.AuditPath))
	for i, p := range incl.AuditPath {
		auditHex[i] = hex.EncodeToString(p)
	}

	receipt := &ComplianceReceipt{
		Version:    "1.0",
		LeafIndex:  leafIndex,
		LeafHash:   hex.EncodeToString(leafHash),
		RawPayload: string(rawPayload),
		InclusionProof: InclusionProofDTO{
			TreeSize:  incl.TreeSize,
			AuditPath: auditHex,
		},
		SignedTreeHead: *sth,
		CreatedAt:      time.Now().Unix(),
	}

	if len(historicalRoot) > 0 {
		receipt.HistoricalRoot = hex.EncodeToString(historicalRoot)
	}

	if constProof != nil && len(constProof.Path) > 0 {
		pathHex := make([]string, len(constProof.Path))
		for i, p := range constProof.Path {
			pathHex[i] = hex.EncodeToString(p)
		}
		receipt.ConsistencyProof = &ConsistencyProofDTO{
			OldSize: constProof.FirstSize,
			NewSize: constProof.SecondSize,
			Path:    pathHex,
		}
	}

	return receipt, nil
}

// Verify verifies a ComplianceReceipt completely offline against a trusted Ed25519 public key.
func Verify(trustedPubKey ed25519.PublicKey, r *ComplianceReceipt) *VerificationReport {
	report := &VerificationReport{
		LeafIndex: r.LeafIndex,
		TreeSize:  r.SignedTreeHead.TreeSize,
		Steps:     make([]VerificationStep, 0, 4),
	}

	fail := func(stepName, errDetails string) *VerificationReport {
		report.Valid = false
		report.Error = errDetails
		report.Steps = append(report.Steps, VerificationStep{
			Name:    stepName,
			Passed:  false,
			Details: errDetails,
		})
		return report
	}

	// Step 1: Recompute RFC 6962 Domain-Separated Leaf Hash (0x00 prefix)
	hasher := merkle.NewSHA256Hasher()
	computedLeafHash := hasher.HashLeaf([]byte(r.RawPayload))
	computedHex := hex.EncodeToString(computedLeafHash)

	if computedHex != r.LeafHash {
		return fail("Leaf Hash Recomputation", fmt.Sprintf("computed hash %s does not match claimed leaf_hash %s (payload tampered)", computedHex, r.LeafHash))
	}
	report.Steps = append(report.Steps, VerificationStep{
		Name:    "Leaf Hash Recomputation (RFC 6962)",
		Passed:  true,
		Details: fmt.Sprintf("SHA-256(0x00 || payload) matches claimed hash %s", computedHex[:16]+"..."),
	})

	// Decode Inclusion Audit Path
	auditPathBytes := make([][]byte, len(r.InclusionProof.AuditPath))
	for i, h := range r.InclusionProof.AuditPath {
		b, err := hex.DecodeString(h)
		if err != nil {
			return fail("Inclusion Proof Decoding", fmt.Sprintf("invalid hex in audit path at index %d: %v", i, err))
		}
		auditPathBytes[i] = b
	}

	nativeInclProof := &merkle.InclusionProof{
		LeafIndex: r.LeafIndex,
		TreeSize:  r.InclusionProof.TreeSize,
		AuditPath: auditPathBytes,
	}

	// Step 2: Inclusion Proof Verification
	var targetHistoricalRoot []byte
	if r.HistoricalRoot != "" {
		b, err := hex.DecodeString(r.HistoricalRoot)
		if err != nil {
			return fail("Historical Root Decoding", fmt.Sprintf("invalid historical root hex: %v", err))
		}
		targetHistoricalRoot = b
	} else {
		// When M == N, historical root is current STH root
		b, err := hex.DecodeString(r.SignedTreeHead.RootHash)
		if err != nil {
			return fail("STH Root Decoding", fmt.Sprintf("invalid STH root hex: %v", err))
		}
		targetHistoricalRoot = b
	}

	if !merkle.VerifyInclusion(hasher, computedLeafHash, targetHistoricalRoot, nativeInclProof) {
		return fail("Inclusion Proof Verification", fmt.Sprintf("merkle audit path fails to reconstruct expected root %s for tree size %d", hex.EncodeToString(targetHistoricalRoot)[:16]+"...", r.InclusionProof.TreeSize))
	}
	report.Steps = append(report.Steps, VerificationStep{
		Name:    "Merkle Inclusion Verification (RFC 6962)",
		Passed:  true,
		Details: fmt.Sprintf("Leaf %d verified in sub-tree of size %d -> Root %s", r.LeafIndex, r.InclusionProof.TreeSize, hex.EncodeToString(targetHistoricalRoot)[:16]+"..."),
	})

	// Step 3: Historical Consistency Proof (if N > M)
	sthRootBytes, err := hex.DecodeString(r.SignedTreeHead.RootHash)
	if err != nil {
		return fail("STH Root Hash Decoding", fmt.Sprintf("invalid hex in STH root: %v", err))
	}

	if r.ConsistencyProof != nil && len(r.ConsistencyProof.Path) > 0 {
		cPathBytes := make([][]byte, len(r.ConsistencyProof.Path))
		for i, h := range r.ConsistencyProof.Path {
			b, err := hex.DecodeString(h)
			if err != nil {
				return fail("Consistency Proof Decoding", fmt.Sprintf("invalid hex in consistency path at index %d: %v", i, err))
			}
			cPathBytes[i] = b
		}

		nativeConstProof := &merkle.ConsistencyProof{
			FirstSize:  r.ConsistencyProof.OldSize,
			SecondSize: r.ConsistencyProof.NewSize,
			Path:       cPathBytes,
		}

		if !merkle.VerifyConsistency(hasher, targetHistoricalRoot, sthRootBytes, nativeConstProof) {
			return fail("Consistency Proof Verification", fmt.Sprintf("consistency path fails to prove Tree(%d) ⊆ Tree(%d)", r.ConsistencyProof.OldSize, r.ConsistencyProof.NewSize))
		}
		report.Steps = append(report.Steps, VerificationStep{
			Name:    "Append-Only Consistency Verification (RFC 9162)",
			Passed:  true,
			Details: fmt.Sprintf("Verified Tree(%d) ⊆ Tree(%d) [Historical Root consistent with Checkpoint Root]", r.ConsistencyProof.OldSize, r.ConsistencyProof.NewSize),
		})
	} else if r.InclusionProof.TreeSize < r.SignedTreeHead.TreeSize {
		return fail("Missing Consistency Proof", fmt.Sprintf("inclusion proof is for Tree(%d) but STH is for Tree(%d) without consistency proof", r.InclusionProof.TreeSize, r.SignedTreeHead.TreeSize))
	}

	// Step 4: Ed25519 Digital Signature & Checkpoint Verification
	sigBytes, err := hex.DecodeString(r.SignedTreeHead.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return fail("Ed25519 Signature Decoding", "invalid signature bytes")
	}

	digest := signer.CanonicalSTHDigest(r.SignedTreeHead.TreeSize, sthRootBytes, r.SignedTreeHead.Timestamp, r.SignedTreeHead.Sequence)
	if !ed25519.Verify(trustedPubKey, digest, sigBytes) {
		return fail("Ed25519 Checkpoint Signature Verification", "cryptographic signature does not match trusted public key")
	}
	report.Steps = append(report.Steps, VerificationStep{
		Name:    "Ed25519 Checkpoint Signature Verification",
		Passed:  true,
		Details: fmt.Sprintf("Signature verified against trusted root public key (Seq: %d, TreeSize: %d)", r.SignedTreeHead.Sequence, r.SignedTreeHead.TreeSize),
	})

	report.Valid = true
	return report
}
