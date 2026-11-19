package githubapp

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type mockProducer struct {
	publishedKey string
	publishedVal []byte
	errToReturn  error
}

func (m *mockProducer) Publish(ctx context.Context, key string, event []byte) error {
	if m.errToReturn != nil {
		return m.errToReturn
	}
	m.publishedKey = key
	m.publishedVal = event
	return nil
}

func signPayload(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestVerifySignature(t *testing.T) {
	secret := "super-secure-webhook-secret-123"
	payload := []byte(`{"zen":"Practicality beats purity."}`)
	validSig := signPayload(payload, secret)

	if !VerifySignature(payload, validSig, secret) {
		t.Fatalf("expected valid signature to verify successfully")
	}

	tamperedPayload := []byte(`{"zen":"Practicality beats purity!"}`)
	if VerifySignature(tamperedPayload, validSig, secret) {
		t.Fatalf("expected tampered payload to fail signature verification")
	}

	invalidSig := "sha256=0000000000000000000000000000000000000000000000000000000000000000"
	if VerifySignature(payload, invalidSig, secret) {
		t.Fatalf("expected forged signature to fail")
	}

	if VerifySignature(payload, "invalidprefix123", secret) {
		t.Fatalf("expected signature missing sha256= prefix to fail")
	}

	if VerifySignature(payload, validSig, "") {
		t.Fatalf("expected empty secret to fail verification")
	}
}

func TestNormalizePush(t *testing.T) {
	pushPayload := []byte(`{
		"ref": "refs/heads/main",
		"head_commit": {
			"id": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4",
			"message": "fix: resolve memory leak in tile engine",
			"timestamp": "2026-11-18T10:00:00Z",
			"author": {
				"name": "Siddharth",
				"username": "siddharth-dev"
			}
		},
		"pusher": {
			"name": "siddharth-dev"
		},
		"repository": {
			"full_name": "org/merklegate"
		}
	}`)

	ev, err := NormalizeEvent("push", pushPayload)
	if err != nil {
		t.Fatalf("failed to normalize push: %v", err)
	}

	if ev.EventType != "git_commit" {
		t.Errorf("expected EventType 'git_commit', got '%s'", ev.EventType)
	}
	if ev.CommitSHA != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4" {
		t.Errorf("expected CommitSHA, got '%s'", ev.CommitSHA)
	}
	if ev.Actor != "siddharth-dev" {
		t.Errorf("expected Actor 'siddharth-dev', got '%s'", ev.Actor)
	}
}

func TestNormalizePullRequestReview(t *testing.T) {
	approvedPayload := []byte(`{
		"action": "submitted",
		"review": {
			"state": "approved",
			"user": { "login": "security-lead" },
			"submitted_at": "2026-11-18T11:00:00Z"
		},
		"pull_request": {
			"number": 42,
			"title": "feat: add zero-knowledge proof verification",
			"head": { "sha": "7d9e4a3b2c1f0e9d8c7b6a5" }
		},
		"repository": { "full_name": "org/merklegate" }
	}`)

	ev, err := NormalizeEvent("pull_request_review", approvedPayload)
	if err != nil {
		t.Fatalf("failed to normalize approved review: %v", err)
	}
	if ev.EventType != "pr_approval" {
		t.Errorf("expected EventType 'pr_approval', got '%s'", ev.EventType)
	}
	if ev.PRNumber != 42 {
		t.Errorf("expected PRNumber 42, got %d", ev.PRNumber)
	}
	if ev.CommitSHA != "7d9e4a3b2c1f0e9d8c7b6a5" {
		t.Errorf("unexpected head sha: %s", ev.CommitSHA)
	}
	if ev.Actor != "security-lead" {
		t.Errorf("expected Actor 'security-lead', got '%s'", ev.Actor)
	}

	rejectedPayload := []byte(`{
		"action": "submitted",
		"review": {
			"state": "changes_requested",
			"user": { "login": "qa-engineer" }
		}
	}`)
	_, err = NormalizeEvent("pull_request_review", rejectedPayload)
	if !errors.Is(err, ErrEventIgnored) {
		t.Fatalf("expected changes_requested review to be ignored, got: %v", err)
	}
}

func TestNormalizeWorkflowRun(t *testing.T) {
	snykScanPayload := []byte(`{
		"action": "completed",
		"workflow_run": {
			"name": "Snyk Container Security Scan",
			"head_sha": "a1b2c3d4e5f60718293a",
			"conclusion": "success",
			"actor": { "login": "ci-bot" }
		},
		"repository": { "full_name": "org/merklegate" }
	}`)

	ev, err := NormalizeEvent("workflow_run", snykScanPayload)
	if err != nil {
		t.Fatalf("failed to normalize workflow_run: %v", err)
	}
	if ev.EventType != "snyk_scan" {
		t.Errorf("expected EventType 'snyk_scan', got '%s'", ev.EventType)
	}
	if ev.CommitSHA != "a1b2c3d4e5f60718293a" {
		t.Errorf("expected head sha, got %s", ev.CommitSHA)
	}

	failedScanPayload := []byte(`{
		"action": "completed",
		"workflow_run": {
			"name": "Snyk Container Security Scan",
			"head_sha": "a1b2c3d4e5f60718293a",
			"conclusion": "failure",
			"actor": { "login": "ci-bot" }
		}
	}`)
	_, err = NormalizeEvent("workflow_run", failedScanPayload)
	if !errors.Is(err, ErrEventIgnored) {
		t.Fatalf("expected failed workflow to be ignored, got: %v", err)
	}
}

func TestReceiverServeHTTP(t *testing.T) {
	secret := "secret-key-99"
	mock := &mockProducer{}
	recv := NewReceiver(Config{
		WebhookSecret: secret,
		Producer:      mock,
	})

	pushPayload := []byte(`{
		"ref": "refs/heads/main",
		"head_commit": {
			"id": "beefdeadbeefdeadbeefdeadbeefdeadbeefdead",
			"author": { "username": "alice" }
		},
		"repository": { "full_name": "acme/repo" }
	}`)

	// 1. Success case: valid signature and push event
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/github", bytes.NewReader(pushPayload))
	req.Header.Set("X-GitHub-Event", "push")
	req.Header.Set("X-Hub-Signature-256", signPayload(pushPayload, secret))
	w := httptest.NewRecorder()

	recv.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected HTTP 202 Accepted, got %d: %s", w.Code, w.Body.String())
	}
	if mock.publishedKey != "beefdeadbeefdeadbeefdeadbeefdeadbeefdead" {
		t.Errorf("expected Kafka message key to be commit SHA, got %s", mock.publishedKey)
	}

	var parsedEvent ComplianceEvent
	if err := json.Unmarshal(mock.publishedVal, &parsedEvent); err != nil {
		t.Fatalf("failed to unmarshal published event: %v", err)
	}
	if parsedEvent.EventType != "git_commit" || parsedEvent.Actor != "alice" {
		t.Errorf("unexpected published event content: %+v", parsedEvent)
	}

	// 2. Failure case: forged signature
	reqForged := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/github", bytes.NewReader(pushPayload))
	reqForged.Header.Set("X-GitHub-Event", "push")
	reqForged.Header.Set("X-Hub-Signature-256", "sha256=invalid")
	wForged := httptest.NewRecorder()

	recv.ServeHTTP(wForged, reqForged)
	if wForged.Code != http.StatusUnauthorized {
		t.Fatalf("expected HTTP 401 Unauthorized for invalid signature, got %d", wForged.Code)
	}

	// 3. Ping event case
	reqPing := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/github", bytes.NewReader([]byte(`{}`)))
	reqPing.Header.Set("X-GitHub-Event", "ping")
	reqPing.Header.Set("X-Hub-Signature-256", signPayload([]byte(`{}`), secret))
	wPing := httptest.NewRecorder()

	recv.ServeHTTP(wPing, reqPing)
	if wPing.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 OK for ping, got %d", wPing.Code)
	}
}
