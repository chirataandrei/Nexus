// Package nexussdk este SDK-ul client oficial pentru Nexus Trust
// Protocol. Este un modul Go separat, fără nicio dependență de codul
// serverului gateway — orice echipă poate să-l adauge într-un agent
// existent în câteva linii de cod, fără să cunoască intern cum
// funcționează Nexus.
//
// Ce face: gestionează automat "bootstrap-ul" de identitate (schimbul
// secretului pe un JWT-SVID efemer), pune token-ul în cache, îl
// reîmprospătează singur înainte să expire și îl atașează pe fiecare
// cerere HTTP — fie direct (Client.Do), fie ca un *http.Client drop-in
// (Client.HTTPClient) care poate înlocui transportul HTTP al oricărui
// SDK existent (ex. clientul oficial OpenAI/Anthropic) fără alte
// modificări de cod.
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

// defaultRefreshSkew este marja de siguranță cu care un token este
// considerat "pe cale să expire" și reîmprospătat din timp, ca nicio
// cerere reală să nu rateze din cauza unei expirări chiar în timpul ei.
const defaultRefreshSkew = 30 * time.Second

// Client este clientul Nexus: o singură instanță per (agent, sarcină).
// Este sigur pentru utilizare concurentă.
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

// Option configurează un Client opțional, la construcție.
type Option func(*Client)

// WithHTTPClient setează clientul HTTP de bază folosit pentru a vorbi cu
// Nexus și cu upstream-urile. Implicit: http.DefaultClient.
func WithHTTPClient(c *http.Client) Option {
	return func(cl *Client) {
		if c != nil {
			cl.httpClient = c
		}
	}
}

// WithScopes cere explicit un subset de scope-uri la emiterea tokenului
// (trebuie să fie un subset din allowed_scopes al agentului în registrul
// Nexus — altfel cererea de token este respinsă). Dacă nu este setat,
// agentul primește toate scope-urile lui permise.
func WithScopes(scopes ...string) Option {
	return func(cl *Client) { cl.scopes = scopes }
}

// WithTTL cere un TTL specific pentru tokenurile emise (limitat în
// continuare de politica serverului). Dacă nu este setat, se folosește
// implicitul serverului (de regulă 5 minute).
func WithTTL(d time.Duration) Option {
	return func(cl *Client) { cl.ttl = d }
}

// New construiește un Client Nexus. baseURL este adresa gateway-ului
// (ex. "https://nexus.compania-ta.com"), agentID/secret sunt cele
// înregistrate de un administrator în registrul de agenți Nexus, iar
// taskID identifică sarcina curentă a agentului (un JWT-SVID Nexus este
// legat strict de o singură sarcină).
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

// tokenRequest/tokenResponse oglindesc forma JSON a endpoint-ului
// POST /nexus/identity/token al gateway-ului. SDK-ul nu importă pachetul
// serverului — doar cunoaște protocolul de pe fir, exact cum ar face
// orice client HTTP independent.
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

// Token returnează un JWT-SVID valid, reîmprospătându-l automat dacă
// este absent sau pe cale să expire. De regulă nu trebuie apelat direct
// — Do și HTTPClient îl folosesc intern — dar este expus pentru cazurile
// în care un apelant are nevoie de token-ul brut (ex. pentru un alt
// transport decât net/http).
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
		return "", fmt.Errorf("nexussdk: nu pot serializa cererea de token: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/nexus/identity/token", bytes.NewReader(raw))
	if err != nil {
		return "", fmt.Errorf("nexussdk: nu pot construi cererea de token: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("nexussdk: cererea de token către %s a eșuat: %w", c.baseURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("nexussdk: gateway-ul a respins cererea de token (status %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("nexussdk: răspuns invalid de la /nexus/identity/token: %w", err)
	}
	if tr.Token == "" {
		return "", fmt.Errorf("nexussdk: gateway-ul a răspuns fără token")
	}

	c.token = tr.Token
	c.expiresAt = time.Unix(tr.ExpiresAt, 0)
	return c.token, nil
}

// Do execută o cerere HTTP prin Nexus, atașând automat un JWT-SVID valid
// pe antetul Authorization. req.URL ar trebui să țintească gateway-ul
// Nexus (ex. baseURL + "/v1/openai/..."), nu upstream-ul direct.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	token, err := c.Token(req.Context())
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return c.httpClient.Do(req)
}

// HTTPClient returnează un *http.Client complet — drop-in replacement —
// care atașează și reîmprospătează automat tokenul Nexus pe orice cerere
// trimisă prin el. Util pentru a "conecta" Nexus la un SDK existent care
// acceptă un *http.Client/http.RoundTripper personalizat (ex. clientul
// oficial OpenAI: openai.NewClient(option.WithHTTPClient(nexusClient.HTTPClient()))).
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
	// Clonăm cererea înainte de a modifica anteturile — un RoundTripper nu
	// ar trebui să mute cererea originală a apelantului.
	cloned := req.Clone(req.Context())
	cloned.Header.Set("Authorization", "Bearer "+token)
	return t.base.RoundTrip(cloned)
}
