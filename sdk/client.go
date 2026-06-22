// Package nexussdk is the official client SDK for Nexus Trust
// Protocol. It's a separate Go module with no dependency on the
// gateway server's code — any team can add it to an existing agent in
// a few lines of code, without needing to know how Nexus works
// internally.
//
// What it does: it automatically handles identity "bootstrap"
// (exchanging the secret for an ephemeral JWT-SVID), caches the token,
// refreshes it on its own before it expires, and attaches it to every
// HTTP request — either directly (Client.Do), or as a drop-in
// *http.Client (Client.HTTPClient) that can replace the HTTP transport
// of any existing SDK (e.g. the official OpenAI/Anthropic client) with
// no other code changes.
package nexussdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// defaultRefreshSkew is the safety margin within which a token is
// considered "about to expire" and refreshed ahead of time, so no real
// request ever fails because of an expiration happening mid-request.
const defaultRefreshSkew = 30 * time.Second

// Client is the Nexus client: one instance per (agent, task). It's safe
// for concurrent use.
type Client struct {
	baseURL    string
	agentID    string
	secret     string
	taskID     string
	httpClient *http.Client
	scopes     []string
	ttl        time.Duration

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

// Option configures an optional Client setting at construction time.
type Option func(*Client)

// WithHTTPClient sets the base HTTP client used to talk to Nexus and to
// the upstreams. Defaults to http.DefaultClient.
func WithHTTPClient(c *http.Client) Option {
	return func(cl *Client) {
		if c != nil {
			cl.httpClient = c
		}
	}
}

// WithScopes explicitly requests a subset of scopes when issuing the
// token (must be a subset of the agent's allowed_scopes in the Nexus
// registry — otherwise the token request is rejected). If not set, the
// agent gets all of its allowed scopes.
func WithScopes(scopes ...string) Option {
	return func(cl *Client) { cl.scopes = scopes }
}

// WithTTL requests a specific TTL for issued tokens (still capped by
// the server's policy). If not set, the server's default is used
// (typically 5 minutes).
func WithTTL(d time.Duration) Option {
	return func(cl *Client) { cl.ttl = d }
}

// New builds a Nexus Client. baseURL is the gateway's address (e.g.
// "https://nexus.your-company.com"), agentID/secret are the ones an
// administrator registered in Nexus's agent registry, and taskID
// identifies the agent's current task (a Nexus JWT-SVID is strictly
// tied to a single task).
func New(baseURL, agentID, secret, taskID string, opts ...Option) *Client {
	c := &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		agentID:    agentID,
		secret:     secret,
		taskID:     taskID,
		httpClient: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// tokenRequest/tokenResponse mirror the JSON shape of the gateway's
// POST /nexus/identity/token endpoint. The SDK doesn't import the
// server's package — it just knows the wire protocol, exactly like any
// independent HTTP client would.
type tokenRequest struct {
	AgentID    string   `json:"agent_id"`
	Secret     string   `json:"secret"`
	TaskID     string   `json:"task_id"`
	Scopes     []string `json:"scopes,omitempty"`
	TTLSeconds int      `json:"ttl_seconds,omitempty"`
}

type tokenResponse struct {
	Token     string   `json:"token"`
	SpiffeID  string   `json:"spiffe_id"`
	Scopes    []string `json:"scopes"`
	IssuedAt  int64    `json:"issued_at"`
	ExpiresAt int64    `json:"expires_at"`
}

// Token returns a valid JWT-SVID, automatically refreshing it if it's
// missing or about to expire. You normally don't need to call this
// directly — Do and HTTPClient use it internally — but it's exported
// for cases where a caller needs the raw token (e.g. for a transport
// other than net/http).
func (c *Client) Token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.token != "" && time.Now().Add(defaultRefreshSkew).Before(c.expiresAt) {
		return c.token, nil
	}
	return c.refreshLocked(ctx)
}

func (c *Client) refreshLocked(ctx context.Context) (string, error) {
	reqBody := tokenRequest{
		AgentID:    c.agentID,
		Secret:     c.secret,
		TaskID:     c.taskID,
		Scopes:     c.scopes,
		TTLSeconds: int(c.ttl.Seconds()),
	}
	raw, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("nexussdk: cannot serialize token request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/nexus/identity/token", bytes.NewReader(raw))
	if err != nil {
		return "", fmt.Errorf("nexussdk: cannot build token request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("nexussdk: token request to %s failed: %w", c.baseURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("nexussdk: the gateway rejected the token request (status %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("nexussdk: invalid response from /nexus/identity/token: %w", err)
	}
	if tr.Token == "" {
		return "", fmt.Errorf("nexussdk: the gateway responded without a token")
	}

	c.token = tr.Token
	c.expiresAt = time.Unix(tr.ExpiresAt, 0)
	return c.token, nil
}

// Do executes an HTTP request through Nexus, automatically attaching a
// valid JWT-SVID to the Authorization header. req.URL should target the
// Nexus gateway (e.g. baseURL + "/v1/openai/..."), not the upstream
// directly.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	token, err := c.Token(req.Context())
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return c.httpClient.Do(req)
}

// HTTPClient returns a full *http.Client — a drop-in replacement —
// that automatically attaches and refreshes the Nexus token on every
// request sent through it. Useful for "plugging" Nexus into an
// existing SDK that accepts a custom *http.Client/http.RoundTripper
// (e.g. the official OpenAI client:
// openai.NewClient(option.WithHTTPClient(nexusClient.HTTPClient()))).
func (c *Client) HTTPClient() *http.Client {
	base := c.httpClient.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	return &http.Client{
		Transport: &authTransport{client: c, base: base},
		Timeout:   c.httpClient.Timeout,
	}
}

type authTransport struct {
	client *Client
	base   http.RoundTripper
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := t.client.Token(req.Context())
	if err != nil {
		return nil, err
	}
	// Clone the request before modifying headers — a RoundTripper
	// shouldn't mutate the caller's original request.
	cloned := req.Clone(req.Context())
	cloned.Header.Set("Authorization", "Bearer "+token)
	return t.base.RoundTrip(cloned)
}
