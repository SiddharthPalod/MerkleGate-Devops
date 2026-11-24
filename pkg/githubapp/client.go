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
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidPrivateKey = errors.New("invalid RSA private key")
	ErrGitHubAPI         = errors.New("github api error")
)

// CheckRunOutput contains title, summary, and detailed Markdown for a GitHub Check Run.
type CheckRunOutput struct {
	Title   string `json:"title"`
	Summary string `json:"summary"`
	Text    string `json:"text,omitempty"`
}

// CheckRunInput parameters for creating or updating a Check Run on GitHub.
type CheckRunInput struct {
	Name        string         `json:"name"`
	HeadSHA     string         `json:"head_sha"`
	Status      string         `json:"status"` // "queued", "in_progress", "completed"
	Conclusion  string         `json:"conclusion,omitempty"` // "success", "failure", "neutral", etc.
	DetailsURL  string         `json:"details_url,omitempty"`
	Output      CheckRunOutput `json:"output"`
}

// Client manages GitHub App authentication and API interactions.
type Client struct {
	appID      int64
	privKey    *rsa.PrivateKey
	baseURL    string
	httpClient *http.Client

	// Token cache per installation ID
	mu          sync.RWMutex
	tokenCache  map[int64]cachedToken
}

type cachedToken struct {
	token     string
	expiresAt time.Time
}

// NewClient creates a GitHub App client using the App ID and RSA Private Key PEM bytes.
func NewClient(appID int64, privKeyPEM []byte) (*Client, error) {
	block, _ := pem.Decode(privKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("%w: failed to decode PEM block", ErrInvalidPrivateKey)
	}

	// Try PKCS#1 first
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS#8
		pkcs8Key, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("%w: neither PKCS#1 nor PKCS#8: %v", ErrInvalidPrivateKey, err)
		}
		var ok bool
		key, ok = pkcs8Key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: key is not RSA", ErrInvalidPrivateKey)
		}
	}

	return &Client{
		appID:      appID,
		privKey:    key,
		baseURL:    "https://api.github.com",
		httpClient: &http.Client{Timeout: 15 * time.Second},
		tokenCache: make(map[int64]cachedToken),
	}, nil
}

// SetBaseURL overrides the API endpoint (useful for mock testing).
func (c *Client) SetBaseURL(url string) {
	c.baseURL = strings.TrimRight(url, "/")
}

// SetHTTPClient overrides the internal http.Client (useful for in-memory mock transports).
func (c *Client) SetHTTPClient(hc *http.Client) {
	if hc != nil {
		c.httpClient = hc
	}
}

// GenerateAppJWT generates a short-lived (10 min) RS256 JWT for GitHub App authentication.
func (c *Client) GenerateAppJWT() (string, error) {
	headerJSON := `{"alg":"RS256","typ":"JWT"}`
	headerEnc := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))

	now := time.Now().Unix()
	claims := map[string]interface{}{
		"iat": now - 60,  // 60 seconds clock skew tolerance
		"exp": now + 500, // Total lifetime 560s (< 10 minutes max allowed from iat by GitHub)
		"iss": c.appID,
	}

	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal jwt claims: %w", err)
	}
	payloadEnc := base64.RawURLEncoding.EncodeToString(claimsBytes)

	message := headerEnc + "." + payloadEnc
	h := sha256.Sum256([]byte(message))

	sig, err := rsa.SignPKCS1v15(rand.Reader, c.privKey, crypto.SHA256, h[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign jwt: %w", err)
	}

	sigEnc := base64.RawURLEncoding.EncodeToString(sig)
	return message + "." + sigEnc, nil
}

// GetInstallationToken returns a valid installation token, using cache when available.
func (c *Client) GetInstallationToken(ctx context.Context, installationID int64) (string, error) {
	c.mu.RLock()
	cached, found := c.tokenCache[installationID]
	c.mu.RUnlock()

	// Return cached token if valid for at least another minute
	if found && time.Now().Add(time.Minute).Before(cached.expiresAt) {
		return cached.token, nil
	}

	jwt, err := c.GenerateAppJWT()
	if err != nil {
		return "", fmt.Errorf("failed to generate app jwt: %w", err)
	}

	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", c.baseURL, installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create access token request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "MerkleGate-Ledger")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("installation token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("%w: status %d: %s", ErrGitHubAPI, resp.StatusCode, string(body))
	}

	var res struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", fmt.Errorf("failed to decode installation token response: %w", err)
	}

	c.mu.Lock()
	c.tokenCache[installationID] = cachedToken{
		token:     res.Token,
		expiresAt: res.ExpiresAt,
	}
	c.mu.Unlock()

	return res.Token, nil
}

// CreateCheckRun publishes a Check Run to GitHub for a specific repository and commit SHA.
func (c *Client) CreateCheckRun(ctx context.Context, installationID int64, ownerRepo string, input CheckRunInput) error {
	token, err := c.GetInstallationToken(ctx, installationID)
	if err != nil {
		return fmt.Errorf("cannot post check run: %w", err)
	}

	url := fmt.Sprintf("%s/repos/%s/check-runs", c.baseURL, ownerRepo)
	bodyBytes, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("failed to marshal check run input: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create check run request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "MerkleGate-Ledger")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("check run creation failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%w: check run failed (status %d): %s", ErrGitHubAPI, resp.StatusCode, string(body))
	}

	return nil
}
