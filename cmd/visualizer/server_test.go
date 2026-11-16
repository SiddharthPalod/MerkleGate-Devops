package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVisualizerServer_API(t *testing.T) {
	server := NewServer()

	// 1. Test GET /api/tree
	req := httptest.NewRequest(http.MethodGet, "/api/tree", nil)
	w := httptest.NewRecorder()
	server.handleGetTree(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}

	var treeResp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &treeResp); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if int(treeResp["size"].(float64)) != 4 {
		t.Fatalf("expected size 4, got %v", treeResp["size"])
	}

	// 2. Test GET /api/proof/inclusion?leafIndex=1
	req = httptest.NewRequest(http.MethodGet, "/api/proof/inclusion?leafIndex=1", nil)
	w = httptest.NewRecorder()
	server.handleInclusionProof(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}

	var inclResp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &inclResp); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if !inclResp["verified"].(bool) {
		t.Fatal("expected inclusion proof to be verified by Go engine")
	}

	// 3. Test GET /api/proof/consistency?oldSize=2
	req = httptest.NewRequest(http.MethodGet, "/api/proof/consistency?oldSize=2", nil)
	w = httptest.NewRecorder()
	server.handleConsistencyProof(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}

	var constResp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &constResp); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if !constResp["verified"].(bool) {
		t.Fatal("expected consistency proof to be verified by Go engine")
	}

	// 4. Test POST /api/tamper
	req = httptest.NewRequest(http.MethodPost, "/api/tamper", nil)
	w = httptest.NewRecorder()
	server.handleTamper(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}

	// Verify inclusion proof fails after tamper
	req = httptest.NewRequest(http.MethodGet, "/api/proof/inclusion?leafIndex=0", nil)
	w = httptest.NewRecorder()
	server.handleInclusionProof(w, req)

	var tamperedResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &tamperedResp)
	if tamperedResp["verified"].(bool) {
		t.Fatal("expected inclusion proof to fail after tampering")
	}

	// 5. Test POST /api/events
	body := strings.NewReader(`{"event": "argocd:deploy:release-v2"}`)
	req = httptest.NewRequest(http.MethodPost, "/api/events", body)
	w = httptest.NewRecorder()
	server.handleAddEvent(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}
}
