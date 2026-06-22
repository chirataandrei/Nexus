package finops

import (
	"testing"
	"time"
)

func TestLedger_AuthorizeAllowsWithinBudget(t *testing.T) {
	l := NewLedger()
	policy := AgentPolicy{AgentID: "agent-1", DailyBudgetUSD: 5.0, MaxTokensPerTask: 1000}

	if err := l.Authorize("agent-1", "task-1", policy); err != nil {
		t.Fatalf("Authorize ar trebui să accepte un agent fără consum: %v", err)
	}
}

func TestLedger_AuthorizeBlocksWhenDailyBudgetExceeded(t *testing.T) {
	l := NewLedger()
	policy := AgentPolicy{AgentID: "agent-1", DailyBudgetUSD: 1.0}

	l.RecordSpend("agent-1", "task-1", 100, 1.0) // exact bugetul

	if err := l.Authorize("agent-1", "task-1", policy); err == nil {
		t.Error("Authorize ar trebui să respingă o cerere când bugetul zilnic e deja epuizat")
	}
}

func TestLedger_AuthorizeBlocksWhenTaskTokenLimitReached(t *testing.T) {
	l := NewLedger()
	policy := AgentPolicy{AgentID: "agent-1", DailyBudgetUSD: 100, MaxTokensPerTask: 500}

	l.RecordSpend("agent-1", "task-1", 500, 0.01)

	if err := l.Authorize("agent-1", "task-1", policy); err == nil {
		t.Error("Authorize ar trebui să respingă atunci când limita de tokeni per sarcină e atinsă")
	}
	// O sarcină diferită a aceluiași agent nu trebuie afectată.
	if err := l.Authorize("agent-1", "task-2", policy); err != nil {
		t.Errorf("o sarcină nouă a aceluiași agent nu ar trebui blocată: %v", err)
	}
}

func TestLedger_RecursiveHallucinationLoopGetsCircuitBroken(t *testing.T) {
	// Simulează exact scenariul din specificație: un agent care, printr-o
	// buclă recurentă, face cereri repetate ce consumă mult cost, până
	// depășește bugetul — Nexus trebuie să-l blocheze înainte de a mai
	// contacta LLM-ul costisitor.
	l := NewLedger()
	policy := AgentPolicy{AgentID: "agent-loop", DailyBudgetUSD: 5.0}

	calls := 0
	for i := 0; i < 100; i++ {
		if err := l.Authorize("agent-loop", "task-x", policy); err != nil {
			break
		}
		calls++
		l.RecordSpend("agent-loop", "task-x", 1000, 1.0) // $1 pe apel
	}

	if calls != 5 {
		t.Errorf("ar trebui exact 5 apeluri permise ($5 buget / $1 per apel), am primit %d", calls)
	}
	if err := l.Authorize("agent-loop", "task-x", policy); err == nil {
		t.Error("după 5 apeluri (=$5 cheltuiți), al 6-lea ar trebui blocat")
	}
}

func TestLedger_RecordSpendAccumulates(t *testing.T) {
	l := NewLedger()
	l.RecordSpend("agent-1", "task-1", 100, 0.5)
	l.RecordSpend("agent-1", "task-1", 50, 0.25)

	snap := snapshotFor(t, l, "agent-1")
	if snap.SpentUSD != 0.75 {
		t.Errorf("spentUSD = %v, vroiam 0.75", snap.SpentUSD)
	}
	if snap.TaskTokens["task-1"] != 150 {
		t.Errorf("tokens task-1 = %d, vroiam 150", snap.TaskTokens["task-1"])
	}
}

func TestLedger_ResetsOnNewDay(t *testing.T) {
	l := NewLedger()
	current := time.Date(2026, 6, 22, 23, 59, 0, 0, time.UTC)
	l.now = func() time.Time { return current }

	l.RecordSpend("agent-1", "task-1", 100, 4.0)
	policy := AgentPolicy{AgentID: "agent-1", DailyBudgetUSD: 5.0}
	if err := l.Authorize("agent-1", "task-1", policy); err != nil {
		t.Fatalf("ar trebui încă sub buget: %v", err)
	}

	// Trece în ziua următoare.
	current = current.Add(2 * time.Hour)
	if err := l.Authorize("agent-1", "task-1", policy); err != nil {
		t.Errorf("bugetul ar trebui resetat după schimbarea zilei UTC: %v", err)
	}
	snap := snapshotFor(t, l, "agent-1")
	if snap.SpentUSD != 0 {
		t.Errorf("spentUSD ar trebui resetat la 0 în noua zi, am primit %v", snap.SpentUSD)
	}
}

func snapshotFor(t *testing.T, l *Ledger, agentID string) AgentUsageSnapshot {
	t.Helper()
	for _, s := range l.Snapshot() {
		if s.AgentID == agentID {
			return s
		}
	}
	t.Fatalf("nu există snapshot pentru agentul %q", agentID)
	return AgentUsageSnapshot{}
}
