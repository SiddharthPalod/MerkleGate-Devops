package integration

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"merklegate/pkg/githubapp"
	"merklegate/pkg/merkle"
	"merklegate/pkg/receipt"
	"merklegate/pkg/signer"
	"merklegate/pkg/storage"
)

type inMemProducer struct {
	eventsCh chan []byte
}

func (p *inMemProducer) Publish(ctx context.Context, key string, event []byte) error {
	p.eventsCh <- event
	return nil
}

func signWebhook(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestGitHubApp_To_ActionGuardrail_E2E(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "githubapp_action_e2e_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	driver, _ := storage.NewFileStorageDriver(tempDir)
	tileStore := storage.NewTileStore(driver)

	_, privKey, _ := signer.GenerateKeypair()
	sig := signer.NewLocalSigner(privKey)
	pubKeyHex := hex.EncodeToString(sig.PublicKey())

	hasher := merkle.NewSHA256Hasher()
	prod := &inMemProducer{eventsCh: make(chan []byte, 10)}
	webhookSecret := "guardrail-test-secret-42"

	receiver := githubapp.NewReceiver(githubapp.Config{
		WebhookSecret: webhookSecret,
		Producer:      prod,
	})

	testCommitSHA := "f8e4b2d1c0a987654321fedcba0987654321abcd"

	// 1. Deliver GitHub 'push' event
	pushPayload := []byte(fmt.Sprintf(`{
		"ref": "refs/heads/main",
		"head_commit": {
			"id": "%s",
			"message": "feat: enterprise compliance guardrail",
			"author": { "username": "lead-architect" }
		},
		"pusher": { "name": "lead-architect" },
		"repository": { "full_name": "acme/corp-core" }
	}`, testCommitSHA))

	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/github", bytes.NewReader(pushPayload))
	req1.Header.Set("X-GitHub-Event", "push")
	req1.Header.Set("X-Hub-Signature-256", signWebhook(pushPayload, webhookSecret))
	w1 := httptest.NewRecorder()

	receiver.ServeHTTP(w1, req1)
	if w1.Code != http.StatusAccepted {
		t.Fatalf("expected push webhook status 202, got %d: %s", w1.Code, w1.Body.String())
	}

	// 2. Deliver GitHub 'pull_request_review' (approved) event
	reviewPayload := []byte(fmt.Sprintf(`{
		"action": "submitted",
		"review": {
			"state": "approved",
			"user": { "login": "security-officer" }
		},
		"pull_request": {
			"number": 99,
			"title": "Security compliance PR",
			"head": { "sha": "%s" }
		},
		"repository": { "full_name": "acme/corp-core" }
	}`, testCommitSHA))

	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/github", bytes.NewReader(reviewPayload))
	req2.Header.Set("X-GitHub-Event", "pull_request_review")
	req2.Header.Set("X-Hub-Signature-256", signWebhook(reviewPayload, webhookSecret))
	w2 := httptest.NewRecorder()

	receiver.ServeHTTP(w2, req2)
	if w2.Code != http.StatusAccepted {
		t.Fatalf("expected pr review webhook status 202, got %d: %s", w2.Code, w2.Body.String())
	}

	// Drain normalized events from channel
	var rawEvents [][]byte
	for i := 0; i < 2; i++ {
		select {
		case ev := <-prod.eventsCh:
			rawEvents = append(rawEvents, ev)
		case <-time.After(1 * time.Second):
			t.Fatalf("timeout waiting for event %d from kafka channel", i)
		}
	}

	// 3. Build Merkle Tree & Persist C2SP Tiles
	tree, err := merkle.NewTree(rawEvents, hasher)
	if err != nil {
		t.Fatalf("failed to build tree: %v", err)
	}

	leafHashes := make([][]byte, len(rawEvents))
	for i, e := range rawEvents {
		leafHashes[i] = hasher.HashLeaf(e)
	}
	if err := tileStore.SaveLeaves(0, leafHashes, rawEvents); err != nil {
		t.Fatalf("failed to save leaves to tile store: %v", err)
	}

	// 4. Sign Tree Head (STH)
	sth, err := sig.SignTreeHead(len(rawEvents), tree.Root.Hash, 1)
	if err != nil {
		t.Fatalf("failed to sign STH: %v", err)
	}

	// 5. Generate and Verify Receipts for both leaves in Go
	receipts := make([]*receipt.ComplianceReceipt, len(rawEvents))
	receiptFiles := make([]string, len(rawEvents))

	for i := 0; i < len(rawEvents); i++ {
		inclProof, err := tree.GenerateInclusionProof(i)
		if err != nil {
			t.Fatalf("failed to generate inclusion proof for leaf %d: %v", i, err)
		}

		rcpt, err := receipt.BuildReceipt(i, rawEvents[i], inclProof, nil, nil, sth)
		if err != nil {
			t.Fatalf("failed to build receipt: %v", err)
		}
		receipts[i] = rcpt

		// Verify in Go
		goReport := receipt.Verify(sig.PublicKey(), rcpt)
		if !goReport.Valid {
			t.Fatalf("Go receipt verification failed for leaf %d: %+v", i, goReport)
		}

		// Save to temporary JSON file for Node.js verification
		rcptPath := filepath.Join(tempDir, fmt.Sprintf("receipt-%d.json", i))
		rcptBytes, _ := json.MarshalIndent(rcpt, "", "  ")
		if err := os.WriteFile(rcptPath, rcptBytes, 0644); err != nil {
			t.Fatalf("failed to write receipt file: %v", err)
		}
		receiptFiles[i] = rcptPath
	}

	t.Logf("✓ Verified Go Receipt Verification: 2 leaves audited, Ed25519 STH passed.")

	// 6. Cross-Platform Node.js Cryptographic Verification Test
	// Invoke Node.js to verify the Go-generated receipts using action/verify.js
	actionVerifyPath, _ := filepath.Abs(filepath.Join("..", "..", "action", "verify.js"))
	actionVerifyPath = filepath.ToSlash(actionVerifyPath)

	verifyScript := fmt.Sprintf(`
		const fs = require('fs');
		const { verifyReceipt } = require('%s');

		const pubKey = '%s';
		const files = %s;

		let allValid = true;
		for (const f of files) {
			const data = JSON.parse(fs.readFileSync(f, 'utf8'));
			const res = verifyReceipt(data, pubKey);
			if (!res.valid) {
				console.error('Node verification failed for ' + f + ':', res.errors);
				allValid = false;
			} else {
				console.log('✓ Node verified leaf ' + data.leaf_index + ' with hash ' + res.leafHash);
			}
		}

		if (!allValid) process.exit(1);
	`, actionVerifyPath, pubKeyHex, func() string {
		b, _ := json.Marshal(receiptFiles)
		return string(b)
	}())

	nodeCmd := exec.Command("node", "-e", verifyScript)
	nodeOut, err := nodeCmd.CombinedOutput()
	t.Logf("Node Verification Output:\n%s", string(nodeOut))
	if err != nil {
		t.Fatalf("Node.js verification of Go-generated receipts failed: %v", err)
	}

	t.Logf("✓ Full Cryptographic Interoperability Confirmed: Go Merkle Engine <-> Node.js Action Guardrail")
}
