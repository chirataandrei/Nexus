// control_handler.go expune API-ul administrativ "kill-switch" (Articolul
// 14 — supervizare umană) și un endpoint de verificare a integrității
// lanțului de conformitate. Orice acțiune de suspendare/reluare este, la
// rândul ei, scrisă în lanțul WORM — un operator nu poate suspenda un
// agent "pe tăcute": gestul însuși devine o înregistrare permanentă.
package compliance

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
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

// SuspendHandler expune POST /nexus/control/suspend.
func SuspendHandler(registry *SuspensionRegistry, chain *Chain) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "metodă neacceptată, folosiți POST", http.StatusMethodNotAllowed)
			return
		}
		var req suspendRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, maxControlRequestBytes)).Decode(&req); err != nil {
			http.Error(w, "corp JSON invalid", http.StatusBadRequest)
			return
		}
		if req.AgentID == "" || req.Reason == "" {
			http.Error(w, "agent_id și reason sunt obligatorii", http.StatusBadRequest)
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

// ResumeHandler expune POST /nexus/control/resume.
func ResumeHandler(registry *SuspensionRegistry, chain *Chain) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "metodă neacceptată, folosiți POST", http.StatusMethodNotAllowed)
			return
		}
		var req resumeRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, maxControlRequestBytes)).Decode(&req); err != nil {
			http.Error(w, "corp JSON invalid", http.StatusBadRequest)
			return
		}
		if req.AgentID == "" {
			http.Error(w, "agent_id este obligatoriu", http.StatusBadRequest)
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

// SuspendedListHandler expune GET /nexus/control/suspended.
func SuspendedListHandler(registry *SuspensionRegistry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "metodă neacceptată, folosiți GET", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(registry.List())
	}
}

// VerifyHandler expune GET /nexus/compliance/verify: rulează VerifyChain
// la cerere, ca un auditor să poată confirma în orice moment că lanțul
// de conformitate nu a fost modificat retroactiv.
func VerifyHandler(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "metodă neacceptată, folosiți GET", http.StatusMethodNotAllowed)
			return
		}
		n, err := VerifyChain(path)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "verified_records": n, "error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "verified_records": n})
	}
}
