// handler.go expune endpoint-ul administrativ prin care un agent face
// "bootstrap": schimbă o singură dată secretul lui pre-distribuit pe un
// JWT-SVID efemer. Acesta este singurul punct din Nexus unde circulă un
// secret pe termen lung — toate cererile ulterioare ale agentului către
// upstream-uri folosesc exclusiv tokenul efemer, nu mai au nevoie de
// secretul original.
package identity

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// TokenRequest este corpul JSON acceptat de endpoint-ul de emitere token.
type TokenRequest struct {
	AgentID string `json:"agent_id"`
	Secret  string `json:"secret"`
	TaskID  string `json:"task_id"`
	// Scopes este opțional: dacă e omis, agentul primește exact
	// AllowedScopes din registru. Dacă e specificat, fiecare scope cerut
	// trebuie să fie deja în AllowedScopes (least privilege — un agent
	// poate cere mai puțin decât are dreptul, niciodată mai mult).
	Scopes []string `json:"scopes,omitempty"`
	// TTLSeconds este opțional; implicit și maxim este controlat de
	// registru/Issuer (implicit 5 minute).
	TTLSeconds int `json:"ttl_seconds,omitempty"`
}

// TokenResponse este răspunsul JSON cu JWT-SVID-ul emis.
type TokenResponse struct {
	Token     string   `json:"token"`
	SpiffeID  string   `json:"spiffe_id"`
	Scopes    []string `json:"scopes"`
	IssuedAt  int64    `json:"issued_at"`
	ExpiresAt int64    `json:"expires_at"`
}

// maxTokenRequestBytes limitează corpul cererii de token, ca să nu se
// poată trimite payload-uri uriașe către un endpoint de autentificare.
const maxTokenRequestBytes = 1 << 16 // 64 KiB

// TokenHandler construiește handler-ul HTTP pentru POST /nexus/identity/token.
// suspension poate fi nil, caz în care se folosește NoopSuspensionChecker.
func TokenHandler(registry *Registry, issuer *Issuer, suspension SuspensionChecker) http.HandlerFunc {
	if suspension == nil {
		suspension = NoopSuspensionChecker{}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "metodă neacceptată, folosiți POST", http.StatusMethodNotAllowed)
			return
		}

		var req TokenRequest
		dec := json.NewDecoder(io.LimitReader(r.Body, maxTokenRequestBytes))
		if err := dec.Decode(&req); err != nil {
			http.Error(w, "corp JSON invalid", http.StatusBadRequest)
			return
		}

		if req.AgentID == "" || req.Secret == "" || req.TaskID == "" {
			http.Error(w, "agent_id, secret și task_id sunt obligatorii", http.StatusBadRequest)
			return
		}

		// Un agent suspendat (kill-switch) nu poate obține nici măcar un
		// token nou, chiar dacă secretul lui de bootstrap este corect —
		// suspendarea este globală și imediată.
		if suspended, reason := suspension.IsSuspended(req.AgentID); suspended {
			slog.Warn("nexus.identity.token_denied_suspended",
				"event", "token_denied_suspended",
				"agent_id", req.AgentID,
				"reason", reason,
			)
			http.Error(w, fmt.Sprintf("agentul este suspendat de un operator: %s", reason), http.StatusForbidden)
			return
		}

		rec, err := registry.Authenticate(req.AgentID, req.Secret)
		if err != nil {
			slog.Warn("nexus.identity.auth_failed",
				"event", "bootstrap_auth_failed",
				"agent_id", req.AgentID,
				"remote_addr", r.RemoteAddr,
			)
			http.Error(w, "autentificare eșuată", http.StatusUnauthorized)
			return
		}

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
			http.Error(w, "nu pot emite tokenul", http.StatusInternalServerError)
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
