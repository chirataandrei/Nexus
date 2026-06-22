// Package proxy implementează nucleul gateway-ului: un reverse proxy
// Layer 7 care interceptează cererile HTTP/REST și JSON-RPC ale
// agenților, le validează, le rutează către upstream-ul corect (model
// LLM extern sau serviciu intern) și le jurnalizează structurat.
//
// Lanțul de procesare per cerere este:
//
//	parsare payload -> rutare -> validare identitate -> autorizare buget
//	-> jurnalizare cerere -> proxy efectiv -> jurnalizare răspuns
//
// Validarea identității (WIMSE/SPIFFE) și autorizarea bugetului (FinOps)
// sunt expuse ca interfețe (Validator, BudgetEnforcer din hooks.go) ca
// implementările reale să se conecteze fără să rescrie acest fișier.
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

// route leagă un prefix de path de un upstream configurat și de
// reverse-proxy-ul stdlib care efectuează transmiterea efectivă.
type route struct {
	prefix          string
	stripPrefix     bool
	name            string
	requiredScope   string
	toolScopes      map[string]string
	pricePerKTokens float64
	proxy           *httputil.ReverseProxy
}

// Server este gateway-ul Nexus complet asamblat: rutele de upstream,
// hook-urile de validare/buget/cost și sink-ul de audit.
type Server struct {
	cfg       *config.Config
	validator Validator
	budget    BudgetEnforcer
	spend     SpendRecorder
	audit     logging.AuditSink
	handler   http.Handler
}

// NewServer construiește gateway-ul pe baza configurației. validator,
// budget, spend și audit pot fi nil, caz în care se folosesc
// implementările implicite (NoopValidator, NoopBudgetEnforcer,
// NoopSpendRecorder, StdoutLogger).
func NewServer(cfg *config.Config, validator Validator, budget BudgetEnforcer, spend SpendRecorder, audit logging.AuditSink) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("proxy: config nu poate fi nil")
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
			return nil, fmt.Errorf("proxy: target_url invalid pentru upstream %q: %w", u.Name, err)
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
	// Prefixele mai lungi (mai specifice) trebuie verificate primele,
	// altfel un upstream generic pe "/v1" ar "ascunde" un upstream mai
	// specific precum "/v1/openai".
	sort.Slice(routes, func(i, j int) bool {
		return len(routes[i].prefix) > len(routes[j].prefix)
	})

	s := &Server{cfg: cfg, validator: validator, budget: budget, spend: spend, audit: audit}
	s.handler = s.buildHandler(routes)
	return s, nil
}

// Handler returnează http.Handler-ul complet al gateway-ului, pregătit
// de a fi montat într-un http.Server.
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
			http.Error(w, "corp de cerere invalid sau prea mare", http.StatusBadRequest)
			return
		}

		rt := matchRoute(routes, r.URL.Path)
		if rt == nil {
			s.audit.RecordRejection(meta, "no_matching_upstream")
			http.Error(w, "niciun upstream configurat pentru acest path", http.StatusNotFound)
			return
		}

		// Punem la dispoziția hook-urilor (Validator, BudgetEnforcer)
		// numele upstream-ului și scope-ul cerut de rută, fără a extinde
		// interfețele lor cu parametri suplimentari.
		meta.UpstreamName = rt.name
		meta.RequiredScope = rt.requiredScope

		// Dacă cererea este un apel de instrument MCP recunoscut explicit
		// în tool_scopes, scope-ul specific acelui instrument suprascrie
		// scope-ul generic al upstream-ului — control de acces la
		// granularitatea unui singur tool, nu a întregii rute.
		if meta.MCPTool != "" && rt.toolScopes != nil {
			if scope, ok := rt.toolScopes[meta.MCPTool]; ok {
				meta.RequiredScope = scope
			}
		}

		ctx := r.Context()

		// Validare identitate (WIMSE/SPIFFE).
		if err := s.validator.Validate(ctx, meta, r); err != nil {
			s.audit.RecordRejection(meta, "identity_validation_failed: "+err.Error())
			http.Error(w, "identitate invalidă sau expirată", http.StatusUnauthorized)
			return
		}

		// Enforcement FinOps în timp real.
		if err := s.budget.Authorize(ctx, meta); err != nil {
			s.audit.RecordRejection(meta, "budget_exceeded: "+err.Error())
			http.Error(w, "limită de buget atinsă pentru acest agent", http.StatusTooManyRequests)
			return
		}

		s.audit.RecordRequest(meta, rt.name)

		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		// meta este atașat contextului cererii interne ca să poată fi
		// recuperat din ModifyResponse (SpendRecorder), care primește doar
		// *http.Response, nu și variabilele locale de aici.
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

// matchRoute găsește prima rută (deja sortată descrescător după
// lungimea prefixului) care se aplică unui path dat.
func matchRoute(routes []route, path string) *route {
	for i := range routes {
		if path == routes[i].prefix || strings.HasPrefix(path, routes[i].prefix+"/") {
			return &routes[i]
		}
	}
	return nil
}

// normalizePrefix asigură că prefixul începe cu "/" și nu are "/" final,
// pentru a face comparațiile de path predictibile.
func normalizePrefix(p string) string {
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return strings.TrimSuffix(p, "/")
}

// statusRecorder capturează codul de status HTTP scris de reverse proxy,
// necesar pentru jurnalizarea răspunsului (RecordResponse).
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// upstreamErrorHandler produce un 502 explicit (cu numele upstream-ului)
// când upstream-ul real e indisponibil, în loc de eroarea generică Go.
func upstreamErrorHandler(name string) func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, _ *http.Request, err error) {
		http.Error(w, fmt.Sprintf("nexus: upstream %q indisponibil: %v", name, err), http.StatusBadGateway)
	}
}

// makeSpendCapture construiește un httputil.ReverseProxy.ModifyResponse
// care citește corpul răspunsului primit de la upstream, îl pasează
// intact către SpendRecorder pentru extragerea costului real, și apoi
// îl restaurează identic, astfel încât clientul (agentul) primește
// exact răspunsul original, neschimbat.
func makeSpendCapture(upstreamName string, pricePerKTokens float64, spend SpendRecorder) func(*http.Response) error {
	return func(resp *http.Response) error {
		meta, ok := requestMetaFromContext(resp.Request.Context())
		if !ok || resp.Body == nil {
			return nil
		}

		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return fmt.Errorf("proxy: nu pot citi răspunsul upstream-ului %q pentru calcul de cost: %w", upstreamName, err)
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))

		spend.RecordSpend(resp.Request.Context(), meta, upstreamName, pricePerKTokens, body)
		return nil
	}
}
