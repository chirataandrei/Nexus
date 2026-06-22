// suspension.go implementează kill-switch-ul Nexus: un registru în
// memorie al agenților suspendați de un operator uman. Este verificat pe
// fiecare validare de identitate (internal/identity.SPIFFEValidator) și
// pe fiecare cerere de token nou — astfel o suspendare are efect
// instantaneu și global, fără a necesita restart sau a aștepta
// expirarea tokenurilor deja emise (Articolul 14 — supervizare umană).
package compliance

import (
	"sync"
	"time"
)

// SuspensionRecord descrie o suspendare activă.
type SuspensionRecord struct {
	AgentID     string    `json:"agent_id"`
	Reason      string    `json:"reason"`
	Operator    string    `json:"operator,omitempty"`
	SuspendedAt time.Time `json:"suspended_at"`
}

// SuspensionRegistry este kill-switch-ul: un set, sigur pentru acces
// concurent, de agenți suspendați. Implementează implicit
// identity.SuspensionChecker (IsSuspended) prin duck-typing, fără ca
// acest pachet să importe internal/identity.
type SuspensionRegistry struct {
	mu        sync.RWMutex
	suspended map[string]SuspensionRecord
}

// NewSuspensionRegistry construiește un registru gol (niciun agent suspendat).
func NewSuspensionRegistry() *SuspensionRegistry {
	return &SuspensionRegistry{suspended: make(map[string]SuspensionRecord)}
}

// Suspend marchează un agent ca suspendat. Apelurile repetate pentru
// același agent actualizează motivul/operatorul/timestamp-ul.
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

// Resume ridică suspendarea unui agent. Returnează false dacă agentul nu
// era suspendat (operațiune fără efect, dar nu o eroare).
func (r *SuspensionRegistry) Resume(agentID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.suspended[agentID]; !ok {
		return false
	}
	delete(r.suspended, agentID)
	return true
}

// IsSuspended implementează identity.SuspensionChecker.
func (r *SuspensionRegistry) IsSuspended(agentID string) (bool, string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rec, ok := r.suspended[agentID]
	if !ok {
		return false, ""
	}
	return true, rec.Reason
}

// List returnează toate suspendările active curent.
func (r *SuspensionRegistry) List() []SuspensionRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]SuspensionRecord, 0, len(r.suspended))
	for _, rec := range r.suspended {
		out = append(out, rec)
	}
	return out
}
