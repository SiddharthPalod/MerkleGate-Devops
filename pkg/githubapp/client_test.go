package githubapp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func generateTestRSAKey(t *testing.T) ([]byte, *rsa.PrivateKey) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	})
	return pemBytes, key
}

func TestNewClient_ValidKey(t *testing.T) {
	pemBytes, _ := generateTestRSAKey(t)
	client, err := NewClient(123456, pemBytes)
	if err != nil {
		t.Fatalf("expected NewClient to succeed, got %v", err)
	}
	if client.appID != 123456 {
		t.Errorf("expected appID 123456, got %d", client.appID)
	}
}

func TestNewClient_InvalidKey(t *testing.T) {
	_, err := NewClient(123456, []byte("invalid pem data"))
	if err == nil {
		t.Fatalf("expected error for invalid PEM, got nil")
	}
}

func TestGenerateAppJWT(t *testing.T) {
	pemBytes, privKey := generateTestRSAKey(t)
	appID := int64(987654)
	client, err := NewClient(appID, pemBytes)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	jwtStr, err := client.GenerateAppJWT()
	if err != nil {
		t.Fatalf("GenerateAppJWT failed: %v", err)
	}

	parts := strings.Split(jwtStr, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts in JWT, got %d", len(parts))
	}

	// 1. Verify Header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("failed to decode header: %v", err)
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("failed to unmarshal header: %v", err)
	}
	if header["alg"] != "RS256" || header["typ"] != "JWT" {
		t.Errorf("unexpected header: %v", header)
	}

	// 2. Verify Payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode payload: %v", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}
	if int64(claims["iss"].(float64)) != appID {
		t.Errorf("expected iss %d, got %v", appID, claims["iss"])
	}

	// 3. Verify RS256 Cryptographic Signature
	message := parts[0] + "." + parts[1]
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("failed to decode signature: %v", err)
	}

	h := sha256.Sum256([]byte(message))
	if err := rsa.VerifyPKCS1v15(&privKey.PublicKey, crypto.SHA256, h[:], sigBytes); err != nil {
		t.Fatalf("RSA signature verification failed: %v", err)
	}
}

func TestGetInstallationToken_And_CreateCheckRun(t *testing.T) {
	pemBytes, _ := generateTestRSAKey(t)
	client, err := NewClient(123456, pemBytes)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	checkRunCreated := false

	mockTransport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/app/installations/42/access_tokens":
			if !strings.HasPrefix(req.Header.Get("Authorization"), "Bearer ") {
				return &http.Response{
					StatusCode: http.StatusUnauthorized,
					Body:       io.NopCloser(strings.NewReader("missing bearer jwt")),
				}, nil
			}
			bodyJSON, _ := json.Marshal(map[string]interface{}{
				"token":      "ghs_mockInstallationToken123",
				"expires_at": time.Now().Add(time.Hour).Format(time.RFC3339),
			})
			return &http.Response{
				StatusCode: http.StatusCreated,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewReader(bodyJSON)),
			}, nil

		case "/repos/octocat/hello-world/check-runs":
			if req.Header.Get("Authorization") != "Bearer ghs_mockInstallationToken123" {
				return &http.Response{
					StatusCode: http.StatusUnauthorized,
					Body:       io.NopCloser(strings.NewReader("invalid token")),
				}, nil
			}
			var input CheckRunInput
			if err := json.NewDecoder(req.Body).Decode(&input); err != nil {
				return &http.Response{
					StatusCode: http.StatusBadRequest,
					Body:       io.NopCloser(strings.NewReader(err.Error())),
				}, nil
			}
			if input.HeadSHA != "deadbeef1234" || input.Conclusion != "success" {
				return &http.Response{
					StatusCode: http.StatusBadRequest,
					Body:       io.NopCloser(strings.NewReader("unexpected check run input")),
				}, nil
			}
			checkRunCreated = true
			resJSON, _ := json.Marshal(map[string]interface{}{"id": 1001, "status": "completed"})
			return &http.Response{
				StatusCode: http.StatusCreated,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewReader(resJSON)),
			}, nil

		default:
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(strings.NewReader("not found")),
			}, nil
		}
	})

	client.SetBaseURL("https://api.github.com")
	client.SetHTTPClient(&http.Client{Transport: mockTransport})

	ctx := context.Background()

	// 1. Test GetInstallationToken
	token, err := client.GetInstallationToken(ctx, 42)
	if err != nil {
		t.Fatalf("GetInstallationToken failed: %v", err)
	}
	if token != "ghs_mockInstallationToken123" {
		t.Errorf("expected token ghs_mockInstallationToken123, got %s", token)
	}

	// 2. Test CreateCheckRun
	err = client.CreateCheckRun(ctx, 42, "octocat/hello-world", CheckRunInput{
		Name:       "MerkleGate / Compliance Ledger",
		HeadSHA:    "deadbeef1234",
		Status:     "completed",
		Conclusion: "success",
		Output: CheckRunOutput{
			Title:   "🛡️ MerkleGate Compliance Audit: APPROVED",
			Summary: "Commit verified in Merkle tree",
		},
	})
	if err != nil {
		t.Fatalf("CreateCheckRun failed: %v", err)
	}

	if !checkRunCreated {
		t.Errorf("expected Check Run to be created on GitHub mock transport")
	}
}
