package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nexus-gateway/internal/config"
	"nexus-gateway/internal/parser"
)

// newMockUpstream starts a local HTTP server that simulates an
// LLM/upstream: it responds 200 and echoes back the received path, so we
// can verify routing (including strip_prefix) works correctly.
func newMockUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Mock-Upstream-Path", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok:" + r.URL.Path))
	}))
}

func TestServer_RoutesToCorrectUpstreamWithStrippedPrefix(t *testing.T) {
	upstream := newMockUpstream(t)
	defer upstream.Close()

	cfg := &config.Config{
		ListenAddr:   ":0",
		MaxBodyBytes: 1 << 20,
		Upstreams: []config.Upstream{
			{Name: "mock", PathPrefix: "/v1/openai", TargetURL: upstream.URL, StripPrefix: true},
		},
	}

	srv, err := NewServer(cfg, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/openai/v1/models", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if got := rec.Body.String(); got != "ok:/v1/models" {
		t.Errorf("upstream received the wrong path (strip_prefix didn't work): %q", got)
	}
}

func TestServer_404WhenNoUpstreamMatches(t *testing.T) {
	cfg := &config.Config{
		ListenAddr: ":0",
		Upstreams: []config.Upstream{
			{Name: "mock", PathPrefix: "/v1/openai", TargetURL: "http://127.0.0.1:1"},
		},
	}
	srv, err := NewServer(cfg, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/unknown", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

type rejectingValidator struct{}

func (rejectingValidator) Validate(_ context.Context, _ *parser.RequestMeta, _ *http.Request) error {
	return errors.New("identity rejected in test")
}

func TestServer_RejectsWhenValidatorFails(t *testing.T) {
	upstream := newMockUpstream(t)
	defer upstream.Close()

	cfg := &config.Config{
		ListenAddr: ":0",
		Upstreams: []config.Upstream{
			{Name: "mock", PathPrefix: "/v1/openai", TargetURL: upstream.URL, StripPrefix: true},
		},
	}
	srv, err := NewServer(cfg, rejectingValidator{}, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/openai/models", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

type capturingValidator struct {
	lastRequiredScope string
}

func (c *capturingValidator) Validate(_ context.Context, meta *parser.RequestMeta, _ *http.Request) error {
	c.lastRequiredScope = meta.RequiredScope
	return nil
}

func TestServer_ToolScopeOverridesUpstreamRequiredScope(t *testing.T) {
	upstream := newMockUpstream(t)
	defer upstream.Close()

	cfg := &config.Config{
		ListenAddr: ":0",
		Upstreams: []config.Upstream{
			{
				Name:          "internal-tools",
				PathPrefix:    "/v1/internal",
				TargetURL:     upstream.URL,
				RequiredScope: "tools:internal:invoke",
				ToolScopes: map[string]string{
					"send_email": "tools:email:send",
					"read_email": "tools:email:read",
				},
			},
		},
	}
	validator := &capturingValidator{}
	srv, err := NewServer(cfg, validator, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	body := `{"jsonrpc":"2.0","method":"tools/call","id":"1","params":{"name":"send_email"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/internal/mcp", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if validator.lastRequiredScope != "tools:email:send" {
		t.Errorf("RequiredScope = %q, want the tool-specific scope (tools:email:send)", validator.lastRequiredScope)
	}
}

func TestServer_FallsBackToUpstreamScopeForUnknownTool(t *testing.T) {
	upstream := newMockUpstream(t)
	defer upstream.Close()

	cfg := &config.Config{
		ListenAddr: ":0",
		Upstreams: []config.Upstream{
			{
				Name:          "internal-tools",
				PathPrefix:    "/v1/internal",
				TargetURL:     upstream.URL,
				RequiredScope: "tools:internal:invoke",
				ToolScopes:    map[string]string{"send_email": "tools:email:send"},
			},
		},
	}
	validator := &capturingValidator{}
	srv, err := NewServer(cfg, validator, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	body := `{"jsonrpc":"2.0","method":"tools/call","id":"1","params":{"name":"unknown_tool"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/internal/mcp", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if validator.lastRequiredScope != "tools:internal:invoke" {
		t.Errorf("RequiredScope = %q, want fallback to the upstream's generic scope", validator.lastRequiredScope)
	}
}

type recordedSpend struct {
	meta         *parser.RequestMeta
	upstreamName string
	price        float64
	body         []byte
}

type fakeSpendRecorder struct {
	mu    sync.Mutex
	calls []recordedSpend
}

func (f *fakeSpendRecorder) RecordSpend(_ context.Context, meta *parser.RequestMeta, upstreamName string, price float64, body []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, recordedSpend{meta: meta, upstreamName: upstreamName, price: price, body: body})
}

func (f *fakeSpendRecorder) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeSpendRecorder) first() recordedSpend {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[0]
}

func TestServer_InvokesSpendRecorderWithResponseBodyIntact(t *testing.T) {
	llmResponseBody := `{"id":"chatcmpl-1","usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(llmResponseBody))
	}))
	defer upstream.Close()

	cfg := &config.Config{
		ListenAddr: ":0",
		Upstreams: []config.Upstream{
			{Name: "mock-llm", PathPrefix: "/v1/openai", TargetURL: upstream.URL, StripPrefix: true, PricePerThousandTokensUSD: 0.002},
		},
	}
	spend := &fakeSpendRecorder{}
	srv, err := NewServer(cfg, nil, nil, spend, nil)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/openai/models", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != llmResponseBody {
		t.Errorf("the response body sent to the client was modified: %q", rec.Body.String())
	}

	if len(spend.calls) != 1 {
		t.Fatalf("SpendRecorder.RecordSpend should be called exactly once, it was called %d times", len(spend.calls))
	}
	call := spend.calls[0]
	if call.upstreamName != "mock-llm" || call.price != 0.002 {
		t.Errorf("wrong parameters passed to RecordSpend: %+v", call)
	}
	if string(call.body) != llmResponseBody {
		t.Errorf("RecordSpend did not receive the real response body: %q", call.body)
	}
}

func TestServer_LongestPrefixWins(t *testing.T) {
	generic := newMockUpstream(t)
	defer generic.Close()
	specific := newMockUpstream(t)
	defer specific.Close()

	cfg := &config.Config{
		ListenAddr: ":0",
		Upstreams: []config.Upstream{
			{Name: "generic", PathPrefix: "/v1", TargetURL: generic.URL, StripPrefix: false},
			{Name: "specific", PathPrefix: "/v1/openai", TargetURL: specific.URL, StripPrefix: false},
		},
	}
	srv, err := NewServer(cfg, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/openai/models", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), "/v1/openai/models") {
		t.Errorf("unexpected response from the wrong upstream: %s", rec.Body.String())
	}
}

// TestServer_RejectsJSONRPCBatch is the regression test for the batch
// bypass: a batch mixing an allowed call with a protected one must never
// reach the upstream (or the validator), whatever the scopes are.
func TestServer_RejectsJSONRPCBatch(t *testing.T) {
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := &config.Config{
		ListenAddr: ":0",
		Upstreams: []config.Upstream{{
			Name:          "mail",
			PathPrefix:    "/v1/mail",
			TargetURL:     upstream.URL,
			RequiredScope: "tools:mail:invoke",
			ToolScopes:    map[string]string{"delete_email": "tools:email:delete"},
		}},
	}
	validator := &capturingValidator{}
	srv, err := NewServer(cfg, validator, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	batch := `[{"jsonrpc":"2.0","method":"ping","id":1},` +
		`{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"delete_email"}}]`
	for _, body := range []string{batch, "\n\t " + batch} {
		req := httptest.NewRequest(http.MethodPost, "/v1/mail/mcp", strings.NewReader(body))
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
		}
	}
	if n := upstreamHits.Load(); n != 0 {
		t.Errorf("upstream received %d request(s); a rejected batch must never be forwarded", n)
	}
	if validator.lastRequiredScope != "" {
		t.Errorf("validator ran for a rejected batch (scope %q)", validator.lastRequiredScope)
	}

	// A single, non-batch call keeps working.
	single := `{"jsonrpc":"2.0","method":"tools/call","id":3,"params":{"name":"delete_email"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/mail/mcp", strings.NewReader(single))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || validator.lastRequiredScope != "tools:email:delete" {
		t.Errorf("single call: status=%d scope=%q", rec.Code, validator.lastRequiredScope)
	}
}

type strictSink struct {
	err      error
	recorded atomic.Int32
}

func (s *strictSink) RecordRequest(*parser.RequestMeta, string)              {}
func (s *strictSink) RecordResponse(*parser.RequestMeta, string, int, int64) {}
func (s *strictSink) RecordRejection(*parser.RequestMeta, string)            {}
func (s *strictSink) RecordRequestStrict(*parser.RequestMeta, string) error {
	s.recorded.Add(1)
	return s.err
}

// TestServer_FailClosedAuditRefusesBeforeForwarding: when the audit sink
// can't store the request record and vetoes, the upstream must never see
// the call and the client gets 503.
func TestServer_FailClosedAuditRefusesBeforeForwarding(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
	}))
	defer upstream.Close()
	cfg := &config.Config{Upstreams: []config.Upstream{{Name: "m", PathPrefix: "/v1/m", TargetURL: upstream.URL}}}

	for _, tc := range []struct {
		name string
		err  error
		want int
		hits int32
	}{
		{"audit ok", nil, http.StatusOK, 1},
		{"audit vetoes", errors.New("disk full"), http.StatusServiceUnavailable, 0},
	} {
		hits.Store(0)
		sink := &strictSink{err: tc.err}
		srv, _ := NewServer(cfg, nil, nil, nil, sink)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/m/x", nil))
		if rec.Code != tc.want || hits.Load() != tc.hits || sink.recorded.Load() != 1 {
			t.Errorf("%s: status=%d hits=%d recorded=%d", tc.name, rec.Code, hits.Load(), sink.recorded.Load())
		}
	}
}

// Streamed (SSE) responses must reach the client as they are produced, not
// when the upstream finally closes — MCP's Streamable HTTP and LLM
// streaming both depend on it — and their usage must still be metered.
func TestServer_StreamsSSEWithoutBufferingAndMetersUsage(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		_, _ = w.Write([]byte("data: {\"delta\":\"hel\"}\n\n"))
		fl.Flush()
		<-release // the stream stays open until the test lets it finish
		_, _ = w.Write([]byte("data: {\"usage\":{\"total_tokens\":42}}\n\ndata: [DONE]\n\n"))
	}))
	defer upstream.Close()

	cfg := &config.Config{
		ListenAddr: ":0",
		Upstreams:  []config.Upstream{{Name: "llm", PathPrefix: "/v1/llm", TargetURL: upstream.URL, StripPrefix: true, PricePerThousandTokensUSD: 0.01}},
	}
	spend := &fakeSpendRecorder{}
	srv, err := NewServer(cfg, nil, nil, spend, nil)
	if err != nil {
		t.Fatal(err)
	}
	gw := httptest.NewServer(srv.Handler())
	defer gw.Close()

	resp, err := http.Get(gw.URL + "/v1/llm/stream") // returns once headers arrive
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 64)
	n, err := resp.Body.Read(buf)
	if err != nil || !strings.Contains(string(buf[:n]), "hel") {
		t.Fatalf("first event did not arrive while the stream was open: %q %v", buf[:n], err)
	}

	close(release)
	rest, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(rest), "[DONE]") {
		t.Errorf("rest of the stream altered or missing: %q", rest)
	}
	resp.Body.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && spend.count() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if spend.count() != 1 || !strings.Contains(string(spend.first().body), `"total_tokens":42`) {
		t.Fatalf("streamed usage not metered: %d calls", spend.count())
	}
}
