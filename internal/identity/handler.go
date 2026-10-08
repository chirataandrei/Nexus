// handler.go exposes the administrative endpoint through which an
// agent does a one-time "bootstrap": exchanging its pre-distributed
// secret for an ephemeral JWT-SVID. This is the only point in Nexus
// where a long-lived secret travels — every subsequent request the
// agent makes to upstreams uses exclusively the ephemeral token, and no
// longer needs the original secret.
package identity

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"
)

// TokenRequest is the JSON body accepted by the token-issuing endpoint.
type TokenRequest struct {
	AgentID string `json:"agent_id"`
	Secret  string `json:"secret"`
	TaskID  string `json:"task_id"`
	// Scopes is optional: if omitted, the agent gets exactly the
	// registry's AllowedScopes. If specified, every requested scope must
	// already be in AllowedScopes (least privilege — an agent may
	// request less than it's entitled to, never more).
	Scopes []string `json:"scopes,omitempty"`
	// TTLSeconds is optional; the default and maximum are controlled by
	// the registry/Issuer (defaults to 5 minutes).
	TTLSeconds int `json:"ttl_seconds,omitempty"`
}

// TokenResponse is the JSON response carrying the issued JWT-SVID.
type TokenResponse struct {
	Token     string   `json:"token"`
	SpiffeID  string   `json:"spiffe_id"`
	Scopes    []string `json:"scopes"`
	IssuedAt  int64    `json:"issued_at"`
	ExpiresAt int64    `json:"expires_at"`
}

// maxTokenRequestBytes limits the size of the token request body, so
// huge payloads can't be sent to an authentication endpoint.
const maxTokenRequestBytes = 1 << 16 // 64 KiB

// Default brute-force limits for the token endpoint: failed attempts
// per client IP, and per (agent, client IP) pair, inside the window.
const (
	DefaultMaxFailuresPerIP    = 20
	DefaultMaxFailuresPerAgent = 5
	DefaultFailureWindow       = time.Minute
)

// TokenLimits groups the brute-force limiters of the token endpoint.
// Failures are keyed by client IP (r.RemoteAddr — X-Forwarded-For is
// deliberately not trusted) and by agent+IP, so an attacker can't lock a
// legitimate agent out from another address.
type TokenLimits struct {
	PerIP    *FailureLimiter
	PerAgent *FailureLimiter
}

// DefaultTokenLimits returns limiters with the default thresholds.
func DefaultTokenLimits() TokenLimits {
	return TokenLimits{
		PerIP:    NewFailureLimiter(DefaultMaxFailuresPerIP, DefaultFailureWindow),
		PerAgent: NewFailureLimiter(DefaultMaxFailuresPerAgent, DefaultFailureWindow),
	}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// TokenHandler builds the HTTP handler for POST /nexus/identity/token
// with the default brute-force limits. suspension may be nil, in which
// case NoopSuspensionChecker is used.
func TokenHandler(registry *Registry, issuer *Issuer, suspension SuspensionChecker) http.HandlerFunc {
	return TokenHandlerWithLimits(registry, issuer, suspension, DefaultTokenLimits())
}

// TokenHandlerWithLimits is TokenHandler with explicit limiters.
func TokenHandlerWithLimits(registry *Registry, issuer *Issuer, suspension SuspensionChecker, limits TokenLimits) http.HandlerFunc {
	if suspension == nil {
		suspension = NoopSuspensionChecker{}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed, use POST", http.StatusMethodNotAllowed)
			return
		}

		// Checked before reading the body or hashing anything, so a
		// blocked client costs the server almost nothing.
		ip := clientIP(r)
		if blocked, wait := limits.PerIP.Blocked(ip); blocked {
			tooManyAttempts(w, ip, "", wait)
			return
		}

		var req TokenRequest
		dec := json.NewDecoder(io.LimitReader(r.Body, maxTokenRequestBytes))
		if err := dec.Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}

		if req.AgentID == "" || req.Secret == "" || req.TaskID == "" {
			http.Error(w, "agent_id, secret, and task_id are required", http.StatusBadRequest)
			return
		}

		agentKey := req.AgentID + "|" + ip
		if blocked, wait := limits.PerAgent.Blocked(agentKey); blocked {
			tooManyAttempts(w, ip, req.AgentID, wait)
			return
		}

		// A suspended agent (kill switch) can't obtain even a new token,
		// even if its bootstrap secret is correct — suspension is global
		// and immediate.
		if suspended, reason := suspension.IsSuspended(req.AgentID); suspended {
			slog.Warn("nexus.identity.token_denied_suspended",
				"event", "token_denied_suspended",
				"agent_id", req.AgentID,
				"reason", reason,
			)
			http.Error(w, fmt.Sprintf("agent is suspended by an operator: %s", reason), http.StatusForbidden)
			return
		}

		rec, err := registry.Authenticate(req.AgentID, req.Secret)
		if err != nil {
			limits.PerIP.Fail(ip)
			limits.PerAgent.Fail(agentKey)
			slog.Warn("nexus.identity.auth_failed",
				"event", "bootstrap_auth_failed",
				"agent_id", req.AgentID,
				"remote_addr", r.RemoteAddr,
			)
			http.Error(w, "authentication failed", http.StatusUnauthorized)
			return
		}

		limits.PerAgent.Reset(agentKey)

		scopes := req.Scopes
		if len(scopes) == 0 {
			scopes = rec.AllowedScopes
		}
		if err := rec.EnsureScopesAllowed(scopes); err != nil {
			slog.Warn("nexus.identity.scope_denied",
				"event", "bootstrap_scope_denied",
				"agent_id", req.AgentID,
				"requested_scopes", scopes,
				"allowed_scopes", rec.AllowedScopes,
			)
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		ttl := time.Duration(req.TTLSeconds) * time.Second
		maxTTL := rec.MaxTTL(registry.DefaultMaxTTL())
		if ttl <= 0 || ttl > maxTTL {
			ttl = maxTTL
		}

		token, claims, err := issuer.IssueSVID(req.AgentID, req.TaskID, scopes, ttl)
		if err != nil {
			slog.Error("nexus.identity.issue_failed", "event", "token_issue_failed", "agent_id", req.AgentID, "error", err.Error())
			http.Error(w, "cannot issue token", http.StatusInternalServerError)
			return
		}

		slog.Info("nexus.identity.token_issued",
			"event", "token_issued",
			"agent_id", claims.AgentID,
			"task_id", claims.TaskID,
			"spiffe_id", claims.Subject,
			"scopes", claims.Scopes,
			"ttl_seconds", int(ttl.Seconds()),
			"jti", claims.JTI,
			"kid", issuer.KeyID(),
		)

		resp := TokenResponse{
			Token:     token,
			SpiffeID:  claims.Subject,
			Scopes:    claims.Scopes,
			IssuedAt:  claims.IssuedAt,
			ExpiresAt: claims.ExpiresAt,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func tooManyAttempts(w http.ResponseWriter, ip, agentID string, wait time.Duration) {
	slog.Warn("nexus.identity.token_rate_limited",
		"event", "token_rate_limited",
		"remote_ip", ip,
		"agent_id", agentID,
		"retry_after_seconds", int(wait.Seconds())+1,
	)
	w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
	http.Error(w, "too many failed attempts, retry later", http.StatusTooManyRequests)
}
