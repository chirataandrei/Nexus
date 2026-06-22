package finops

import (
	"context"
	"testing"

	"nexus-gateway/internal/parser"
)

func TestEnforcer_AllowsWithoutVerifiedIdentity(t *testing.T) {
	policies := newTestPolicyRegistry(t)
	e := NewEnforcer(policies, NewLedger())

	meta := &parser.RequestMeta{} // no VerifiedAgentID (e.g. NoopValidator)
	if err := e.Authorize(context.Background(), meta); err != nil {
		t.Errorf("without a verified identity, Enforcer should not block: %v", err)
	}
}

func TestEnforcer_BlocksAfterBudgetExceeded(t *testing.T) {
	policies := newTestPolicyRegistry(t) // agent-1: $5.0/day
	ledger := NewLedger()
	e := NewEnforcer(policies, ledger)

	meta := &parser.RequestMeta{VerifiedAgentID: "agent-1", VerifiedTaskID: "task-1"}

	if err := e.Authorize(context.Background(), meta); err != nil {
		t.Fatalf("the first request should be allowed: %v", err)
	}

	ledger.RecordSpend("agent-1", "task-1", 1000, 5.0) // exactly the budget

	if err := e.Authorize(context.Background(), meta); err == nil {
		t.Error("Enforcer should block once the daily budget is exhausted")
	}
}

func TestEnforcer_UsesPerAgentPolicyNotGlobalDefault(t *testing.T) {
	policies := newTestPolicyRegistry(t) // default: $1.0/day, agent-1: $5.0/day
	ledger := NewLedger()
	e := NewEnforcer(policies, ledger)

	ledger.RecordSpend("agent-1", "task-1", 1000, 2.0) // above the $1 default, below agent-1's $5

	meta := &parser.RequestMeta{VerifiedAgentID: "agent-1", VerifiedTaskID: "task-1"}
	if err := e.Authorize(context.Background(), meta); err != nil {
		t.Errorf("agent-1 has its own $5 policy, shouldn't be blocked at $2 spent: %v", err)
	}

	otherMeta := &parser.RequestMeta{VerifiedAgentID: "agent-without-policy", VerifiedTaskID: "task-1"}
	ledger.RecordSpend("agent-without-policy", "task-1", 1000, 1.0) // equal to the $1 default
	if err := e.Authorize(context.Background(), otherMeta); err == nil {
		t.Error("an agent without its own policy should use the $1 default and be blocked")
	}
}
