// enforcer.go conține implementarea reală a proxy.BudgetEnforcer:
// verifică, ÎNAINTE ca cererea să ajungă la modelul LLM, dacă agentul a
// epuizat deja bugetul zilnic sau limita de tokeni alocată sarcinii
// curente. Înlocuiește proxy.NoopBudgetEnforcer prin aceeași interfață
// deja pregătită în pachetul proxy — fără alte modificări acolo.
package finops

import (
	"context"

	"nexus-gateway/internal/parser"
)

// Enforcer implementează proxy.BudgetEnforcer pe baza unui Ledger și a
// unui PolicyRegistry.
type Enforcer struct {
	policies *PolicyRegistry
	ledger   *Ledger
}

// NewEnforcer construiește un Enforcer.
func NewEnforcer(policies *PolicyRegistry, ledger *Ledger) *Enforcer {
	return &Enforcer{policies: policies, ledger: ledger}
}

// Authorize implementează proxy.BudgetEnforcer. Folosește identitatea
// VERIFICATĂ (meta.VerifiedAgentID, populată de identity.SPIFFEValidator)
// — niciodată antetul declarat și nesigur — pentru a decide dacă cererea
// poate continua spre upstream.
//
// Dacă nicio identitate verificată nu este prezentă (de exemplu un
// mediu de testare care folosește proxy.NoopValidator), Enforcer nu
// aplică nicio restricție: politica de buget este legată explicit de
// agenți cunoscuți, nu de cereri anonime.
func (e *Enforcer) Authorize(_ context.Context, meta *parser.RequestMeta) error {
	agentID := meta.VerifiedAgentID
	if agentID == "" {
		return nil
	}
	policy := e.policies.For(agentID)
	return e.ledger.Authorize(agentID, meta.VerifiedTaskID, policy)
}
