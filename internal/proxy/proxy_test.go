package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"nexus-gateway/internal/config"
	"nexus-gateway/internal/parser"
)

// newMockUpstream pornește un server HTTP local care simulează un model
// LLM/upstream: răspunde 200 și ecouă path-ul primit, ca să putem verifica
// că rutarea (inclusiv strip_prefix) funcționează corect.
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
		t.Fatalf("NewServer a eșuat: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/openai/v1/models", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, vroiam %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if got := rec.Body.String(); got != "ok:/v1/models" {
		t.Errorf("upstream a primit path greșit (strip_prefix nu a funcționat): %q", got)
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
		t.Fatalf("NewServer a eșuat: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/necunoscut", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, vroiam %d", rec.Code, http.StatusNotFound)
	}
}

type rejectingValidator struct{}

func (rejectingValidator) Validate(_ context.Context, _ *parser.RequestMeta, _ *http.Request) error {
	return errors.New("identitate respinsă în test")
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
		t.Fatalf("NewServer a eșuat: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/openai/models", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, vroiam %d", rec.Code, http.StatusUnauthorized)
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
		t.Fatalf("NewServer a eșuat: %v", err)
	}

	body := `{"jsonrpc":"2.0","method":"tools/call","id":"1","params":{"name":"send_email"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/internal/mcp", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if validator.lastRequiredScope != "tools:email:send" {
		t.Errorf("RequiredScope = %q, vroiam scope-ul specific tool-ului (tools:email:send)", validator.lastRequiredScope)
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
		t.Fatalf("NewServer a eșuat: %v", err)
	}

	body := `{"jsonrpc":"2.0","method":"tools/call","id":"1","params":{"name":"unknown_tool"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/internal/mcp", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if validator.lastRequiredScope != "tools:internal:invoke" {
		t.Errorf("RequiredScope = %q, vroiam fallback la scope-ul generic al upstream-ului", validator.lastRequiredScope)
	}
}

type recordedSpend struct {
	meta         *parser.RequestMeta
	upstreamName string
	price        float64
	body         []byte
}

type fakeSpendRecorder struct {
	calls []recordedSpend
}

func (f *fakeSpendRecorder) RecordSpend(_ context.Context, meta *parser.RequestMeta, upstreamName string, price float64, body []byte) {
	f.calls = append(f.calls, recordedSpend{meta: meta, upstreamName: upstreamName, price: price, body: body})
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
		t.Fatalf("NewServer a eșuat: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/openai/models", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != llmResponseBody {
		t.Errorf("corpul răspunsului trimis clientului a fost modificat: %q", rec.Body.String())
	}

	if len(spend.calls) != 1 {
		t.Fatalf("SpendRecorder.RecordSpend ar trebui apelat exact o dată, a fost apelat %d ori", len(spend.calls))
	}
	call := spend.calls[0]
	if call.upstreamName != "mock-llm" || call.price != 0.002 {
		t.Errorf("parametri greșiți transmiși către RecordSpend: %+v", call)
	}
	if string(call.body) != llmResponseBody {
		t.Errorf("RecordSpend nu a primit corpul real al răspunsului: %q", call.body)
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
		t.Fatalf("NewServer a eșuat: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/openai/models", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), "/v1/openai/models") {
		t.Errorf("răspuns inesperat de la upstream greșit: %s", rec.Body.String())
	}
}
