package finops

import (
	"context"
	"testing"

	"nexus-gateway/internal/parser"
)

func TestEnforcer_AllowsWithoutVerifiedIdentity(t *testing.T) {
	policies := newTestPolicyRegistry(t)
	e := NewEnforcer(policies, NewLedger())

	meta := &parser.RequestMeta{} // fără VerifiedAgentID (ex. NoopValidator)
	if err := e.Authorize(context.Background(), meta); err != nil {
		t.Errorf("fără identitate verificată, Enforcer nu ar trebui să blocheze: %v", err)
	}
}

func TestEnforcer_BlocksAfterBudgetExceeded(t *testing.T) {
	policies := newTestPolicyRegistry(t) // agent-1: $5.0/zi
	ledger := NewLedger()
	e := NewEnforcer(policies, ledger)

	meta := &parser.RequestMeta{VerifiedAgentID: "agent-1", VerifiedTaskID: "task-1"}

	if err := e.Authorize(context.Background(), meta); err != nil {
		t.Fatalf("prima cerere ar trebui permisă: %v", err)
	}

	ledger.RecordSpend("agent-1", "task-1", 1000, 5.0) // exact bugetul

	if err := e.Authorize(context.Background(), meta); err == nil {
		t.Error("Enforcer ar trebui să blocheze după ce bugetul zilnic e epuizat")
	}
}

func TestEnforcer_UsesPerAgentPolicyNotGlobalDefault(t *testing.T) {
	policies := newTestPolicyRegistry(t) // default: $1.0/zi, agent-1: $5.0/zi
	ledger := NewLedger()
	e := NewEnforcer(policies, ledger)

	ledger.RecordSpend("agent-1", "task-1", 1000, 2.0) // peste default-ul de $1, sub cei $5 ai agent-1

	meta := &parser.RequestMeta{VerifiedAgentID: "agent-1", VerifiedTaskID: "task-1"}
	if err := e.Authorize(context.Background(), meta); err != nil {
		t.Errorf("agent-1 are politică proprie de $5, nu ar trebui blocat la $2 cheltuiți: %v", err)
	}

	otherMeta := &parser.RequestMeta{VerifiedAgentID: "agent-fara-politica", VerifiedTaskID: "task-1"}
	ledger.RecordSpend("agent-fara-politica", "task-1", 1000, 1.0) // egal cu default-ul de $1
	if err := e.Authorize(context.Background(), otherMeta); err == nil {
		t.Error("un agent fără politică proprie ar trebui să folosească implicitul de $1 și să fie blocat")
	}
}
