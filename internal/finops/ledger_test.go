package finops

import (
	"testing"
	"time"
)

func TestLedger_AuthorizeAllowsWithinBudget(t *testing.T) {
	l := NewLedger()
	policy := AgentPolicy{AgentID: "agent-1", DailyBudgetUSD: 5.0, MaxTokensPerTask: 1000}

	if _, err := l.Authorize("agent-1", "task-1", policy); err != nil {
		t.Fatalf("Authorize should accept an agent with no spending: %v", err)
	}
}

func TestLedger_AuthorizeBlocksWhenDailyBudgetExceeded(t *testing.T) {
	l := NewLedger()
	policy := AgentPolicy{AgentID: "agent-1", DailyBudgetUSD: 1.0}

	l.RecordSpend("agent-1", "task-1", 100, 1.0) // exactly the budget

	if _, err := l.Authorize("agent-1", "task-1", policy); err == nil {
		t.Error("Authorize should reject a request once the daily budget is already exhausted")
	}
}

func TestLedger_AuthorizeBlocksWhenTaskTokenLimitReached(t *testing.T) {
	l := NewLedger()
	policy := AgentPolicy{AgentID: "agent-1", DailyBudgetUSD: 100, MaxTokensPerTask: 500}

	l.RecordSpend("agent-1", "task-1", 500, 0.01)

	if _, err := l.Authorize("agent-1", "task-1", policy); err == nil {
		t.Error("Authorize should reject once the per-task token limit is reached")
	}
	// A different task for the same agent should not be affected.
	if _, err := l.Authorize("agent-1", "task-2", policy); err != nil {
		t.Errorf("a new task for the same agent should not be blocked: %v", err)
	}
}

func TestLedger_RecursiveHallucinationLoopGetsCircuitBroken(t *testing.T) {
	// Simulates exactly the scenario from the spec: an agent that, through
	// a recurring loop, makes repeated requests that consume a lot of
	// cost, until it exceeds the budget — Nexus must block it before it
	// can contact the costly LLM again.
	l := NewLedger()
	policy := AgentPolicy{AgentID: "agent-loop", DailyBudgetUSD: 5.0}

	calls := 0
	for i := 0; i < 100; i++ {
		if _, err := l.Authorize("agent-loop", "task-x", policy); err != nil {
			break
		}
		calls++
		l.RecordSpend("agent-loop", "task-x", 1000, 1.0) // $1 per call
	}

	if calls != 5 {
		t.Errorf("expected exactly 5 allowed calls ($5 budget / $1 per call), got %d", calls)
	}
	if _, err := l.Authorize("agent-loop", "task-x", policy); err == nil {
		t.Error("after 5 calls (=$5 spent), the 6th should be blocked")
	}
}

func TestLedger_RecordSpendAccumulates(t *testing.T) {
	l := NewLedger()
	l.RecordSpend("agent-1", "task-1", 100, 0.5)
	l.RecordSpend("agent-1", "task-1", 50, 0.25)

	snap := snapshotFor(t, l, "agent-1")
	if snap.SpentUSD != 0.75 {
		t.Errorf("spentUSD = %v, want 0.75", snap.SpentUSD)
	}
	if snap.TaskTokens["task-1"] != 150 {
		t.Errorf("tokens task-1 = %d, want 150", snap.TaskTokens["task-1"])
	}
}

func TestLedger_ResetsOnNewDay(t *testing.T) {
	l := NewLedger()
	current := time.Date(2026, 6, 22, 23, 59, 0, 0, time.UTC)
	l.now = func() time.Time { return current }

	l.RecordSpend("agent-1", "task-1", 100, 4.0)
	policy := AgentPolicy{AgentID: "agent-1", DailyBudgetUSD: 5.0}
	if _, err := l.Authorize("agent-1", "task-1", policy); err != nil {
		t.Fatalf("should still be under budget: %v", err)
	}

	// Roll over to the next day.
	current = current.Add(2 * time.Hour)
	if _, err := l.Authorize("agent-1", "task-1", policy); err != nil {
		t.Errorf("the budget should be reset after the UTC day rolls over: %v", err)
	}
	snap := snapshotFor(t, l, "agent-1")
	if snap.SpentUSD != 0 {
		t.Errorf("spentUSD should be reset to 0 on the new day, got %v", snap.SpentUSD)
	}
}

func snapshotFor(t *testing.T, l *Ledger, agentID string) AgentUsageSnapshot {
	t.Helper()
	for _, s := range l.Snapshot() {
		if s.AgentID == agentID {
			return s
		}
	}
	t.Fatalf("no snapshot found for agent %q", agentID)
	return AgentUsageSnapshot{}
}
