// Package proxy implements the core of the gateway: a Layer 7 reverse
// proxy that intercepts agents' HTTP/REST and JSON-RPC requests,
// validates them, routes them to the right upstream (external LLM
// model or internal service), and logs them in a structured way.
//
// The per-request processing chain is:
//
//	parse payload -> route -> validate identity -> authorize budget
//	-> log request -> proxy the call -> log response
//
// Identity validation (WIMSE/SPIFFE) and budget authorization (FinOps)
// are exposed as interfaces (Validator, BudgetEnforcer in hooks.go) so
// real implementations can plug in without rewriting this file.
package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
	"time"

	"nexus-gateway/internal/config"
	"nexus-gateway/internal/logging"
	"nexus-gateway/internal/parser"
)

// route ties a path prefix to a configured upstream and to the stdlib
// reverse proxy that performs the actual forwarding.
type route struct {
	prefix          string
	stripPrefix     bool
	name            string
	requiredScope   string
	toolScopes      map[string]string
	pricePerKTokens float64
	proxy           *httputil.ReverseProxy
}

// Server is the fully assembled Nexus gateway: upstream routes, the
// validation/budget/cost hooks, and the audit sink.
type Server struct {
	cfg       *config.Config
	validator Validator
	budget    BudgetEnforcer
	spend     SpendRecorder
	audit     logging.AuditSink
	handler   http.Handler
}

// NewServer builds the gateway from the given configuration. validator,
// budget, spend, and audit may be nil, in which case the default
// implementations are used (NoopValidator, NoopBudgetEnforcer,
// NoopSpendRecorder, StdoutLogger).
func NewServer(cfg *config.Config, validator Validator, budget BudgetEnforcer, spend SpendRecorder, audit logging.AuditSink) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("proxy: config must not be nil")
	}
	if validator == nil {
		validator = NoopValidator{}
	}
	if budget == nil {
		budget = NoopBudgetEnforcer{}
	}
	if spend == nil {
		spend = NoopSpendRecorder{}
	}
	if audit == nil {
		audit = logging.NewStdoutLogger()
	}

	routes := make([]route, 0, len(cfg.Upstreams))
	for _, u := range cfg.Upstreams {
		target, err := url.Parse(u.TargetURL)
		if err != nil {
			return nil, fmt.Errorf("proxy: invalid target_url for upstream %q: %w", u.Name, err)
		}
		rp := httputil.NewSingleHostReverseProxy(target)
		rp.ErrorHandler = upstreamErrorHandler(u.Name)
		rp.ModifyResponse = makeSpendCapture(u.Name, u.PricePerThousandTokensUSD, spend)

		routes = append(routes, route{
			prefix:          normalizePrefix(u.PathPrefix),
			stripPrefix:     u.StripPrefix,
			name:            u.Name,
			requiredScope:   u.RequiredScope,
			toolScopes:      u.ToolScopes,
			pricePerKTokens: u.PricePerThousandTokensUSD,
			proxy:           rp,
		})
	}
	// Longer (more specific) prefixes must be checked first, otherwise a
	// generic upstream on "/v1" would "shadow" a more specific one like
	// "/v1/openai".
	sort.Slice(routes, func(i, j int) bool {
		return len(routes[i].prefix) > len(routes[j].prefix)
	})

	s := &Server{cfg: cfg, validator: validator, budget: budget, spend: spend, audit: audit}
	s.handler = s.buildHandler(routes)
	return s, nil
}

// Handler returns the gateway's complete http.Handler, ready to be
// mounted on an http.Server.
func (s *Server) Handler() http.Handler {
	return s.handler
}

func (s *Server) buildHandler(routes []route) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		if s.cfg.MaxBodyBytes > 0 {
			r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
		}

		meta, _, err := parser.Parse(r)
		if err != nil {
			http.Error(w, "invalid or oversized request body", http.StatusBadRequest)
			return
		}

		rt := matchRoute(routes, r.URL.Path)
		if rt == nil {
			s.audit.RecordRejection(meta, "no_matching_upstream")
			http.Error(w, "no upstream configured for this path", http.StatusNotFound)
			return
		}

		// Make the upstream name and the route's required scope available
		// to the hooks (Validator, BudgetEnforcer) without extending their
		// interfaces with extra parameters.
		meta.UpstreamName = rt.name
		meta.RequiredScope = rt.requiredScope

		// If the request is an MCP tool call explicitly recognized in
		// tool_scopes, that specific tool's scope overrides the upstream's
		// generic scope — access control at the granularity of a single
		// tool, not the whole route.
		if meta.MCPTool != "" && rt.toolScopes != nil {
			if scope, ok := rt.toolScopes[meta.MCPTool]; ok {
				meta.RequiredScope = scope
			}
		}

		ctx := r.Context()

		// Identity validation (WIMSE/SPIFFE).
		if err := s.validator.Validate(ctx, meta, r); err != nil {
			s.audit.RecordRejection(meta, "identity_validation_failed: "+err.Error())
			http.Error(w, "invalid or expired identity", http.StatusUnauthorized)
			return
		}

		// Real-time FinOps enforcement.
		if err := s.budget.Authorize(ctx, meta); err != nil {
			s.audit.RecordRejection(meta, "budget_exceeded: "+err.Error())
			http.Error(w, "budget limit reached for this agent", http.StatusTooManyRequests)
			return
		}

		s.audit.RecordRequest(meta, rt.name)

		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		// meta is attached to the internal request's context so it can be
		// retrieved from ModifyResponse (SpendRecorder), which only
		// receives *http.Response, not the local variables defined here.
		req := r.Clone(withRequestMeta(ctx, meta))
		if rt.stripPrefix {
			req.URL.Path = strings.TrimPrefix(r.URL.Path, rt.prefix)
			if req.URL.Path == "" {
				req.URL.Path = "/"
			}
		}

		rt.proxy.ServeHTTP(rec, req)

		s.audit.RecordResponse(meta, rt.name, rec.status, time.Since(start).Milliseconds())
	})
}

// matchRoute finds the first route (already sorted in descending order
// of prefix length) that applies to a given path.
func matchRoute(routes []route, path string) *route {
	for i := range routes {
		if path == routes[i].prefix || strings.HasPrefix(path, routes[i].prefix+"/") {
			return &routes[i]
		}
	}
	return nil
}

// normalizePrefix ensures the prefix starts with "/" and has no
// trailing "/", to make path comparisons predictable.
func normalizePrefix(p string) string {
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return strings.TrimSuffix(p, "/")
}

// statusRecorder captures the HTTP status code written by the reverse
// proxy, needed for logging the response (RecordResponse).
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// upstreamErrorHandler produces an explicit 502 (with the upstream's
// name) when the real upstream is unavailable, instead of Go's generic
// error.
func upstreamErrorHandler(name string) func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, _ *http.Request, err error) {
		http.Error(w, fmt.Sprintf("nexus: upstream %q is unavailable: %v", name, err), http.StatusBadGateway)
	}
}

// makeSpendCapture builds an httputil.ReverseProxy.ModifyResponse that
// reads the response body received from the upstream, passes it intact
// to SpendRecorder for real cost extraction, and then restores it
// identically, so the client (the agent) receives exactly the original,
// unchanged response.
func makeSpendCapture(upstreamName string, pricePerKTokens float64, spend SpendRecorder) func(*http.Response) error {
	return func(resp *http.Response) error {
		meta, ok := requestMetaFromContext(resp.Request.Context())
		if !ok || resp.Body == nil {
			return nil
		}

		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return fmt.Errorf("proxy: cannot read upstream %q's response for cost calculation: %w", upstreamName, err)
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))

		spend.RecordSpend(resp.Request.Context(), meta, upstreamName, pricePerKTokens, body)
		return nil
	}
}
