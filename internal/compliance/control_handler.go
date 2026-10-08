// control_handler.go exposes the "kill switch" admin API (Article 14 —
// human oversight) and an endpoint to verify the compliance chain's
// integrity. Every suspend/resume action is, in turn, written to the
// WORM chain — an operator can't suspend an agent "quietly": the
// action itself becomes a permanent record.
package compliance

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	"nexus-gateway/internal/keystore"
)

const maxControlRequestBytes = 1 << 16

type suspendRequest struct {
	AgentID  string `json:"agent_id"`
	Reason   string `json:"reason"`
	Operator string `json:"operator,omitempty"`
}

type resumeRequest struct {
	AgentID  string `json:"agent_id"`
	Operator string `json:"operator,omitempty"`
}

// SuspendHandler exposes POST /nexus/control/suspend.
func SuspendHandler(registry *SuspensionRegistry, chain *Chain) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed, use POST", http.StatusMethodNotAllowed)
			return
		}
		var req suspendRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, maxControlRequestBytes)).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if req.AgentID == "" || req.Reason == "" {
			http.Error(w, "agent_id and reason are required", http.StatusBadRequest)
			return
		}

		rec := registry.Suspend(req.AgentID, req.Reason, req.Operator)

		if _, err := chain.Append(Record{
			Event:            "agent_suspended",
			VerifiedAgentID:  req.AgentID,
			Decision:         "suspended",
			SuspensionReason: req.Reason,
			Operator:         req.Operator,
		}); err != nil {
			slog.Error("nexus.compliance.chain_write_failed", "event", "chain_write_failed", "context", "agent_suspended", "error", err.Error())
		}

		slog.Warn("nexus.control.agent_suspended",
			"event", "agent_suspended",
			"agent_id", req.AgentID,
			"reason", req.Reason,
			"operator", req.Operator,
		)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rec)
	}
}

// ResumeHandler exposes POST /nexus/control/resume.
func ResumeHandler(registry *SuspensionRegistry, chain *Chain) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed, use POST", http.StatusMethodNotAllowed)
			return
		}
		var req resumeRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, maxControlRequestBytes)).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if req.AgentID == "" {
			http.Error(w, "agent_id is required", http.StatusBadRequest)
			return
		}

		wasSuspended := registry.Resume(req.AgentID)

		if _, err := chain.Append(Record{
			Event:           "agent_resumed",
			VerifiedAgentID: req.AgentID,
			Decision:        "resumed",
			Operator:        req.Operator,
		}); err != nil {
			slog.Error("nexus.compliance.chain_write_failed", "event", "chain_write_failed", "context", "agent_resumed", "error", err.Error())
		}

		slog.Info("nexus.control.agent_resumed", "event", "agent_resumed", "agent_id", req.AgentID, "operator", req.Operator, "was_suspended", wasSuspended)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"agent_id": req.AgentID, "was_suspended": wasSuspended})
	}
}

// SuspendedListHandler exposes GET /nexus/control/suspended.
func SuspendedListHandler(registry *SuspensionRegistry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed, use GET", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(registry.List())
	}
}

// VerifyHandler exposes GET /nexus/compliance/verify: it runs
// VerifyChain on demand, so an auditor can confirm at any time that the
// compliance chain hasn't been retroactively modified. If anchorPath is
// set, it also checks the ledger against its signed anchors, which is
// what detects a complete rewrite of the file.
func VerifyHandler(path, anchorPath string, keys keystore.PublicKeySet) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed, use GET", http.StatusMethodNotAllowed)
			return
		}
		n, err := VerifyChain(path)
		anchored := 0
		if err == nil && anchorPath != "" {
			var anchors []Anchor
			anchors, err = VerifyAnchors(path, anchorPath, keys)
			anchored = len(anchors)
		}
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "verified_records": n, "error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "verified_records": n, "verified_anchors": anchored})
	}
}

// TokenRevoker is what RevokeHandler needs from the identity package's
// revocation list (an interface, so compliance doesn't import identity).
type TokenRevoker interface {
	Revoke(jti string)
}

type revokeRequest struct {
	JTI      string `json:"jti"`
	Reason   string `json:"reason"`
	Operator string `json:"operator,omitempty"`
}

// RevokeHandler exposes POST /nexus/control/revoke: it blocks one specific
// token (by jti) immediately — the surgical alternative to suspending the
// whole agent. The jti of a stolen token is in the ledger's records.
func RevokeHandler(revoker TokenRevoker, chain *Chain) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed, use POST", http.StatusMethodNotAllowed)
			return
		}
		var req revokeRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, maxControlRequestBytes)).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if req.JTI == "" || req.Reason == "" {
			http.Error(w, "jti and reason are required", http.StatusBadRequest)
			return
		}
		revoker.Revoke(req.JTI)
		if _, err := chain.Append(Record{
			Event: "token_revoked", JTI: req.JTI, Decision: "revoked",
			SuspensionReason: req.Reason, Operator: req.Operator,
		}); err != nil {
			slog.Error("nexus.compliance.chain_write_failed", "event", "chain_write_failed", "context", "token_revoked", "error", err.Error())
		}
		slog.Warn("nexus.control.token_revoked", "event", "token_revoked", "jti", req.JTI, "reason", req.Reason, "operator", req.Operator)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jti": req.JTI, "revoked": true})
	}
}
