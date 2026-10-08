// enforcer.go contains the real implementation of proxy.BudgetEnforcer:
// it checks, BEFORE the request reaches the LLM model, whether the
// agent has already exhausted its daily budget or the token limit
// allocated to the current task. It replaces proxy.NoopBudgetEnforcer
// through the same interface already prepared in the proxy package —
// no other changes needed there.
package finops

import (
	"context"

	"nexus-gateway/internal/parser"
)

// Enforcer implements proxy.BudgetEnforcer on top of a Ledger and a
// PolicyRegistry.
type Enforcer struct {
	policies *PolicyRegistry
	ledger   *Ledger
}

// NewEnforcer builds an Enforcer.
func NewEnforcer(policies *PolicyRegistry, ledger *Ledger) *Enforcer {
	return &Enforcer{policies: policies, ledger: ledger}
}

// Authorize implements proxy.BudgetEnforcer. It uses the VERIFIED
// identity (meta.VerifiedAgentID, populated by identity.SPIFFEValidator)
// — never the unsafe, client-declared header — to decide whether the
// request can proceed to the upstream.
//
// If no verified identity is present (e.g. a test environment using
// proxy.NoopValidator), Enforcer applies no restriction: budget policy
// is explicitly tied to known agents, not to anonymous requests.
func (e *Enforcer) Authorize(_ context.Context, meta *parser.RequestMeta) error {
	agentID := meta.VerifiedAgentID
	if agentID == "" {
		return nil
	}
	policy := e.policies.For(agentID)
	reserved, err := e.ledger.Authorize(agentID, meta.VerifiedTaskID, policy)
	if err != nil {
		return err
	}
	meta.BudgetReservedUSD = reserved
	return nil
}

// Release implements proxy.BudgetReleaser: it gives back the worst-case
// cost reserved by Authorize once the request is done. Safe to call more
// than once.
func (e *Enforcer) Release(meta *parser.RequestMeta) {
	if meta.BudgetReservedUSD > 0 {
		e.ledger.Release(meta.VerifiedAgentID, meta.BudgetReservedUSD)
		meta.BudgetReservedUSD = 0
	}
}
