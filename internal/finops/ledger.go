// ledger.go tracks, in memory, each agent's real consumption: how much
// it has spent today (reset on UTC day rollover) and how many tokens it
// has used in each task (task_id) — the dimension an agent caught in a
// recurring hallucination loop can blow up quickly.
//
// Scaling note: Ledger lives in a single process's memory. Multiple
// Nexus instances running in parallel would need a shared store (e.g.
// Redis), but the architecture (the Authorize/RecordSpend interfaces)
// stays the same.
package finops

import (
	"fmt"
	"sync"
	"time"
)

// taskUsage tracks the tokens consumed by a single task (task_id).
type taskUsage struct {
	tokens int
}

// agentState is an agent's daily state.
type agentState struct {
	day      string // "2006-01-02" in UTC
	spentUSD float64
	tasks    map[string]*taskUsage
}

// Ledger is the consumption ledger, safe for concurrent access.
type Ledger struct {
	mu     sync.Mutex
	agents map[string]*agentState
	now    func() time.Time // injectable in tests
}

// NewLedger builds an empty Ledger.
func NewLedger() *Ledger {
	return &Ledger{
		agents: make(map[string]*agentState),
		now:    time.Now,
	}
}

// ensureFreshLocked returns the agent's current state, automatically
// resetting it if the UTC day has rolled over. The caller must hold
// l.mu.
func (l *Ledger) ensureFreshLocked(agentID string) *agentState {
	today := l.now().UTC().Format("2006-01-02")
	st, ok := l.agents[agentID]
	if !ok || st.day != today {
		st = &agentState{day: today, tasks: make(map[string]*taskUsage)}
		l.agents[agentID] = st
	}
	return st
}

// Authorize is the "hard" pre-request check: it rejects immediately,
// before contacting any LLM, if the agent has already exhausted its
// daily budget or the token limit for the current task.
func (l *Ledger) Authorize(agentID, taskID string, policy AgentPolicy) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	st := l.ensureFreshLocked(agentID)

	if policy.DailyBudgetUSD > 0 && st.spentUSD >= policy.DailyBudgetUSD {
		return fmt.Errorf(
			"finops: daily budget exhausted for agent %q ($%.4f of $%.2f spent today)",
			agentID, st.spentUSD, policy.DailyBudgetUSD,
		)
	}

	if policy.MaxTokensPerTask > 0 {
		if tu, ok := st.tasks[taskID]; ok && tu.tokens >= policy.MaxTokensPerTask {
			return fmt.Errorf(
				"finops: token limit reached for this task (agent %q, task %q: %d of %d tokens) — possible recurring hallucination loop",
				agentID, taskID, tu.tokens, policy.MaxTokensPerTask,
			)
		}
	}

	return nil
}

// RecordSpend accumulates the cost and tokens of a completed call. It's
// called after the LLM's response has been received (only then is the
// real consumption known), so the agent's *next* request is evaluated
// correctly by Authorize.
func (l *Ledger) RecordSpend(agentID, taskID string, tokens int, costUSD float64) {
	l.mu.Lock()
	defer l.mu.Unlock()

	st := l.ensureFreshLocked(agentID)
	st.spentUSD += costUSD

	tu, ok := st.tasks[taskID]
	if !ok {
		tu = &taskUsage{}
		st.tasks[taskID] = tu
	}
	tu.tokens += tokens
}

// AgentUsageSnapshot is an immutable copy of an agent's state, used by
// the dashboard/API to expose current consumption.
type AgentUsageSnapshot struct {
	AgentID    string         `json:"agent_id"`
	Date       string         `json:"date"`
	SpentUSD   float64        `json:"spent_usd"`
	TaskTokens map[string]int `json:"task_tokens"`
}

// Snapshot returns a copy of the current state of every agent known to
// the ledger (that has had at least one authorized or recorded request
// today).
func (l *Ledger) Snapshot() []AgentUsageSnapshot {
	l.mu.Lock()
	defer l.mu.Unlock()

	out := make([]AgentUsageSnapshot, 0, len(l.agents))
	for agentID, st := range l.agents {
		tasks := make(map[string]int, len(st.tasks))
		for taskID, tu := range st.tasks {
			tasks[taskID] = tu.tokens
		}
		out = append(out, AgentUsageSnapshot{
			AgentID:    agentID,
			Date:       st.day,
			SpentUSD:   st.spentUSD,
			TaskTokens: tasks,
		})
	}
	return out
}
