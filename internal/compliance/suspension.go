// suspension.go implements Nexus's kill switch: an in-memory registry
// of agents suspended by a human operator. It's checked on every
// identity validation (internal/identity.SPIFFEValidator) and on every
// new token request — so a suspension takes effect instantly and
// globally, with no need for a restart or to wait for already-issued
// tokens to expire (Article 14 — human oversight).
package compliance

import (
	"sync"
	"time"
)

// SuspensionRecord describes an active suspension.
type SuspensionRecord struct {
	AgentID     string    `json:"agent_id"`
	Reason      string    `json:"reason"`
	Operator    string    `json:"operator,omitempty"`
	SuspendedAt time.Time `json:"suspended_at"`
}

// SuspensionRegistry is the kill switch: a set, safe for concurrent
// access, of suspended agents. It implicitly implements
// identity.SuspensionChecker (IsSuspended) through duck typing, without
// this package importing internal/identity.
type SuspensionRegistry struct {
	mu        sync.RWMutex
	suspended map[string]SuspensionRecord
}

// NewSuspensionRegistry builds an empty registry (no agent suspended).
func NewSuspensionRegistry() *SuspensionRegistry {
	return &SuspensionRegistry{suspended: make(map[string]SuspensionRecord)}
}

// Suspend marks an agent as suspended. Repeated calls for the same
// agent update the reason/operator/timestamp.
func (r *SuspensionRegistry) Suspend(agentID, reason, operator string) SuspensionRecord {
	rec := SuspensionRecord{
		AgentID:     agentID,
		Reason:      reason,
		Operator:    operator,
		SuspendedAt: time.Now().UTC(),
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.suspended[agentID] = rec
	return rec
}

// restore re-installs a suspension read back from the ledger, keeping
// its original timestamp.
func (r *SuspensionRegistry) restore(rec SuspensionRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.suspended[rec.AgentID] = rec
}

// Resume lifts an agent's suspension. Returns false if the agent wasn't
// suspended (a no-op, not an error).
func (r *SuspensionRegistry) Resume(agentID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.suspended[agentID]; !ok {
		return false
	}
	delete(r.suspended, agentID)
	return true
}

// IsSuspended implements identity.SuspensionChecker.
func (r *SuspensionRegistry) IsSuspended(agentID string) (bool, string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rec, ok := r.suspended[agentID]
	if !ok {
		return false, ""
	}
	return true, rec.Reason
}

// List returns every currently active suspension.
func (r *SuspensionRegistry) List() []SuspensionRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]SuspensionRecord, 0, len(r.suspended))
	for _, rec := range r.suspended {
		out = append(out, rec)
	}
	return out
}
