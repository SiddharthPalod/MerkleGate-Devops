package githubapp

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var (
	ErrInvalidSignature = errors.New("invalid webhook signature")
	ErrMissingSignature = errors.New("missing X-Hub-Signature-256 header")
	ErrMissingEvent     = errors.New("missing X-GitHub-Event header")
	ErrEventIgnored     = errors.New("event type or state ignored")
)

// EventProducer abstracts publishing compliance events into Kafka or an in-memory queue.
type EventProducer interface {
	Publish(ctx context.Context, key string, event []byte) error
}

// ComplianceEvent is the normalized canonical representation indexed in MerkleGate.
type ComplianceEvent struct {
	EventType string                 `json:"event_type"` // e.g. "git_commit", "pr_approval", "snyk_scan", "ci_pass"
	CommitSHA string                 `json:"commit_sha,omitempty"`
	PRNumber  int                    `json:"pr_number,omitempty"`
	Actor     string                 `json:"actor,omitempty"`
	Timestamp int64                  `json:"timestamp"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// Config holds settings for the GitHub App webhook receiver.
type Config struct {
	WebhookSecret string
	Producer      EventProducer
}

// Receiver handles GitHub webhook HTTP deliveries.
type Receiver struct {
	cfg Config
}

func NewReceiver(cfg Config) *Receiver {
	return &Receiver{cfg: cfg}
}

// VerifySignature validates GitHub's HMAC-SHA256 signature in constant time.
func VerifySignature(payload []byte, signatureHeader string, secret string) bool {
	if secret == "" {
		// If secret is unconfigured, fail verification for safety.
		return false
	}
	if !strings.HasPrefix(signatureHeader, "sha256=") {
		return false
	}
	actualHex := strings.TrimPrefix(signatureHeader, "sha256=")
	actualSig, err := hex.DecodeString(actualHex)
	if err != nil {
		return false
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expectedSig := mac.Sum(nil)

	return subtle.ConstantTimeCompare(actualSig, expectedSig) == 1
}

// NormalizeEvent transforms raw GitHub payloads into a standard ComplianceEvent.
func NormalizeEvent(eventType string, payload []byte) (*ComplianceEvent, error) {
	switch eventType {
	case "push":
		return normalizePush(payload)
	case "pull_request_review":
		return normalizePullRequestReview(payload)
	case "pull_request":
		return normalizePullRequest(payload)
	case "workflow_run":
		return normalizeWorkflowRun(payload)
	case "check_run":
		return normalizeCheckRun(payload)
	default:
		return nil, fmt.Errorf("%w: unsupported event %s", ErrEventIgnored, eventType)
	}
}

func normalizePush(payload []byte) (*ComplianceEvent, error) {
	var body struct {
		Ref        string `json:"ref"`
		Before     string `json:"before"`
		After      string `json:"after"`
		HeadCommit struct {
			ID        string `json:"id"`
			Message   string `json:"message"`
			Timestamp string `json:"timestamp"`
			Author    struct {
				Name     string `json:"name"`
				Username string `json:"username"`
			} `json:"author"`
		} `json:"head_commit"`
		Pusher struct {
			Name string `json:"name"`
		} `json:"pusher"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
	}

	if err := json.Unmarshal(payload, &body); err != nil {
		return nil, fmt.Errorf("malformed push payload: %w", err)
	}

	commitSHA := body.HeadCommit.ID
	if commitSHA == "" {
		commitSHA = body.After
	}
	if commitSHA == "" || commitSHA == "0000000000000000000000000000000000000000" {
		return nil, fmt.Errorf("%w: deleted branch or empty commit", ErrEventIgnored)
	}

	actor := body.Pusher.Name
	if actor == "" {
		actor = body.HeadCommit.Author.Username
	}
	if actor == "" {
		actor = body.HeadCommit.Author.Name
	}

	ts := time.Now().Unix()
	if body.HeadCommit.Timestamp != "" {
		if parsed, err := time.Parse(time.RFC3339, body.HeadCommit.Timestamp); err == nil {
			ts = parsed.Unix()
		}
	}

	return &ComplianceEvent{
		EventType: "git_commit",
		CommitSHA: commitSHA,
		Actor:     actor,
		Timestamp: ts,
		Details: map[string]interface{}{
			"ref":        body.Ref,
			"repo":       body.Repository.FullName,
			"message":    body.HeadCommit.Message,
			"event_from": "github_app",
		},
	}, nil
}

func normalizePullRequestReview(payload []byte) (*ComplianceEvent, error) {
	var body struct {
		Action string `json:"action"` // e.g. "submitted"
		Review struct {
			State string `json:"state"` // e.g. "approved", "changes_requested", "commented"
			User  struct {
				Login string `json:"login"`
			} `json:"user"`
			SubmittedAt string `json:"submitted_at"`
		} `json:"review"`
		PullRequest struct {
			Number int `json:"number"`
			Head   struct {
				SHA string `json:"sha"`
			} `json:"head"`
			Title string `json:"title"`
		} `json:"pull_request"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
	}

	if err := json.Unmarshal(payload, &body); err != nil {
		return nil, fmt.Errorf("malformed pull_request_review payload: %w", err)
	}

	if strings.ToLower(body.Review.State) != "approved" {
		return nil, fmt.Errorf("%w: review state %s is not approved", ErrEventIgnored, body.Review.State)
	}

	ts := time.Now().Unix()
	if body.Review.SubmittedAt != "" {
		if parsed, err := time.Parse(time.RFC3339, body.Review.SubmittedAt); err == nil {
			ts = parsed.Unix()
		}
	}

	return &ComplianceEvent{
		EventType: "pr_approval",
		CommitSHA: body.PullRequest.Head.SHA,
		PRNumber:  body.PullRequest.Number,
		Actor:     body.Review.User.Login,
		Timestamp: ts,
		Details: map[string]interface{}{
			"pr_title":   body.PullRequest.Title,
			"repo":       body.Repository.FullName,
			"state":      body.Review.State,
			"event_from": "github_app",
		},
	}, nil
}

func normalizePullRequest(payload []byte) (*ComplianceEvent, error) {
	var body struct {
		Action      string `json:"action"` // "closed"
		PullRequest struct {
			Number int  `json:"number"`
			Merged bool `json:"merged"`
			Head   struct {
				SHA string `json:"sha"`
			} `json:"head"`
			MergedBy struct {
				Login string `json:"login"`
			} `json:"merged_by"`
			MergedAt string `json:"merged_at"`
			Title    string `json:"title"`
		} `json:"pull_request"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
	}

	if err := json.Unmarshal(payload, &body); err != nil {
		return nil, fmt.Errorf("malformed pull_request payload: %w", err)
	}

	// Only record PR merges
	if body.Action != "closed" || !body.PullRequest.Merged {
		return nil, fmt.Errorf("%w: pull_request action %s (merged=%v) ignored", ErrEventIgnored, body.Action, body.PullRequest.Merged)
	}

	ts := time.Now().Unix()
	if body.PullRequest.MergedAt != "" {
		if parsed, err := time.Parse(time.RFC3339, body.PullRequest.MergedAt); err == nil {
			ts = parsed.Unix()
		}
	}

	return &ComplianceEvent{
		EventType: "pr_merge",
		CommitSHA: body.PullRequest.Head.SHA,
		PRNumber:  body.PullRequest.Number,
		Actor:     body.PullRequest.MergedBy.Login,
		Timestamp: ts,
		Details: map[string]interface{}{
			"pr_title":   body.PullRequest.Title,
			"repo":       body.Repository.FullName,
			"event_from": "github_app",
		},
	}, nil
}

func normalizeWorkflowRun(payload []byte) (*ComplianceEvent, error) {
	var body struct {
		Action      string `json:"action"` // "completed"
		WorkflowRun struct {
			Name       string `json:"name"`
			HeadSHA    string `json:"head_sha"`
			Conclusion string `json:"conclusion"` // "success", "failure"
			UpdatedAt  string `json:"updated_at"`
			Actor      struct {
				Login string `json:"login"`
			} `json:"actor"`
		} `json:"workflow_run"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
	}

	if err := json.Unmarshal(payload, &body); err != nil {
		return nil, fmt.Errorf("malformed workflow_run payload: %w", err)
	}

	if strings.ToLower(body.WorkflowRun.Conclusion) != "success" {
		return nil, fmt.Errorf("%w: workflow conclusion %s is not success", ErrEventIgnored, body.WorkflowRun.Conclusion)
	}

	nameLower := strings.ToLower(body.WorkflowRun.Name)
	eventType := "ci_pass"
	if strings.Contains(nameLower, "snyk") || strings.Contains(nameLower, "scan") || strings.Contains(nameLower, "trivy") || strings.Contains(nameLower, "security") {
		eventType = "snyk_scan"
	}

	ts := time.Now().Unix()
	if body.WorkflowRun.UpdatedAt != "" {
		if parsed, err := time.Parse(time.RFC3339, body.WorkflowRun.UpdatedAt); err == nil {
			ts = parsed.Unix()
		}
	}

	return &ComplianceEvent{
		EventType: eventType,
		CommitSHA: body.WorkflowRun.HeadSHA,
		Actor:     body.WorkflowRun.Actor.Login,
		Timestamp: ts,
		Details: map[string]interface{}{
			"workflow_name": body.WorkflowRun.Name,
			"conclusion":    body.WorkflowRun.Conclusion,
			"repo":          body.Repository.FullName,
			"event_from":    "github_app",
		},
	}, nil
}

func normalizeCheckRun(payload []byte) (*ComplianceEvent, error) {
	var body struct {
		Action   string `json:"action"` // "completed"
		CheckRun struct {
			Name       string `json:"name"`
			HeadSHA    string `json:"head_sha"`
			Conclusion string `json:"conclusion"` // "success"
			CompletedAt string `json:"completed_at"`
		} `json:"check_run"`
		Sender struct {
			Login string `json:"login"`
		} `json:"sender"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
	}

	if err := json.Unmarshal(payload, &body); err != nil {
		return nil, fmt.Errorf("malformed check_run payload: %w", err)
	}

	if strings.ToLower(body.CheckRun.Conclusion) != "success" {
		return nil, fmt.Errorf("%w: check_run conclusion %s is not success", ErrEventIgnored, body.CheckRun.Conclusion)
	}

	nameLower := strings.ToLower(body.CheckRun.Name)
	eventType := "ci_pass"
	if strings.Contains(nameLower, "snyk") || strings.Contains(nameLower, "scan") || strings.Contains(nameLower, "trivy") || strings.Contains(nameLower, "security") {
		eventType = "snyk_scan"
	}

	ts := time.Now().Unix()
	if body.CheckRun.CompletedAt != "" {
		if parsed, err := time.Parse(time.RFC3339, body.CheckRun.CompletedAt); err == nil {
			ts = parsed.Unix()
		}
	}

	return &ComplianceEvent{
		EventType: eventType,
		CommitSHA: body.CheckRun.HeadSHA,
		Actor:     body.Sender.Login,
		Timestamp: ts,
		Details: map[string]interface{}{
			"check_name": body.CheckRun.Name,
			"conclusion": body.CheckRun.Conclusion,
			"repo":       body.Repository.FullName,
			"event_from": "github_app",
		},
	}, nil
}

// ServeHTTP handles GitHub webhook requests.
func (recv *Receiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	// Verify HMAC-SHA256 signature if a secret is configured
	if recv.cfg.WebhookSecret != "" {
		sigHeader := r.Header.Get("X-Hub-Signature-256")
		if sigHeader == "" {
			http.Error(w, "Missing X-Hub-Signature-256 header", http.StatusUnauthorized)
			return
		}
		if !VerifySignature(bodyBytes, sigHeader, recv.cfg.WebhookSecret) {
			http.Error(w, "Invalid signature", http.StatusUnauthorized)
			return
		}
	}

	eventType := r.Header.Get("X-GitHub-Event")
	if eventType == "" {
		http.Error(w, "Missing X-GitHub-Event header", http.StatusBadRequest)
		return
	}

	// Ping event check (GitHub sends this on webhook registration)
	if eventType == "ping" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","message":"pong"}`))
		return
	}

	event, err := NormalizeEvent(eventType, bodyBytes)
	if err != nil {
		if errors.Is(err, ErrEventIgnored) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "ignored",
				"reason":  err.Error(),
				"event":   eventType,
			})
			return
		}
		http.Error(w, fmt.Sprintf("Failed to parse event: %v", err), http.StatusBadRequest)
		return
	}

	eventJSON, err := json.Marshal(event)
	if err != nil {
		http.Error(w, "Failed to marshal compliance event", http.StatusInternalServerError)
		return
	}

	// Dispatch to Kafka or Queue
	if recv.cfg.Producer != nil {
		publishKey := event.CommitSHA
		if publishKey == "" {
			publishKey = event.EventType
		}
		if err := recv.cfg.Producer.Publish(r.Context(), publishKey, eventJSON); err != nil {
			http.Error(w, fmt.Sprintf("Kafka dispatch failed: %v", err), http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "queued",
		"event_type":  event.EventType,
		"commit_sha":  event.CommitSHA,
		"actor":       event.Actor,
		"timestamp":   event.Timestamp,
	})
}
