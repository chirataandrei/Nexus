// policy.go contains per-agent financial policies: the maximum daily
// budget (in USD) and the per-task token limit. These are defined by an
// administrator — by default via configs/finops_policies.json, but
// modifiable at runtime through the dashboard (Upsert).
package finops

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sync"
)

// FallbackMaxCostPerRequestUSD is the worst-case cost reserved per request
// for a budgeted agent whose policy sets no max_cost_per_request_usd (and
// the registry no default). The reservation is what makes the budget hold
// under concurrency, so it is on unless a value is configured; the actual
// reservation is min(daily budget, this). Configure a realistic figure to
// allow more requests in flight.
const FallbackMaxCostPerRequestUSD = 1.0

// effective fills in the safe reservation for a budgeted policy that has
// none, so a burst can never overshoot the budget by default.
func effective(p AgentPolicy) AgentPolicy {
	if p.DailyBudgetUSD > 0 && p.MaxCostPerRequestUSD <= 0 {
		p.MaxCostPerRequestUSD = math.Min(p.DailyBudgetUSD, FallbackMaxCostPerRequestUSD)
	}
	return p
}

// AgentPolicy describes an agent's financial policy.
type AgentPolicy struct {
	AgentID string `json:"agent_id"`
	// DailyBudgetUSD is the maximum amount the agent can spend in a
	// calendar (UTC) day. 0 = no budget limit.
	DailyBudgetUSD float64 `json:"daily_budget_usd"`
	// MaxTokensPerTask is the maximum number of tokens the agent can
	// consume in a single task (task_id) — the direct barrier against a
	// recurring hallucination loop. 0 = no limit.
	MaxTokensPerTask int `json:"max_tokens_per_task"`
	// MaxCostPerRequestUSD is the worst-case cost of a single request.
	// When set, Authorize reserves it up front (and releases it once the
	// request completes), so concurrent in-flight requests can't
	// collectively overshoot DailyBudgetUSD. 0 = no reservation: the
	// budget is only checked against already-recorded spend, so a burst
	// of simultaneous requests can exceed it. 0 is not "off" for a
	// budgeted agent: it falls back to min(budget, FallbackMaxCostPerRequestUSD).
	MaxCostPerRequestUSD float64 `json:"max_cost_per_request_usd"`
}

// policiesFile is the on-disk JSON format.
type policiesFile struct {
	DefaultDailyBudgetUSD   float64       `json:"default_daily_budget_usd"`
	DefaultMaxTokensPerTask int           `json:"default_max_tokens_per_task"`
	DefaultMaxCostPerReqUSD float64       `json:"default_max_cost_per_request_usd"`
	Agents                  []AgentPolicy `json:"agents"`
}

// PolicyRegistry holds per-agent policies, plus the default values used
// for any agent without an explicit entry.
type PolicyRegistry struct {
	mu                      sync.RWMutex
	defaultDailyBudgetUSD   float64
	defaultMaxTokensPerTask int
	defaultMaxCostPerReqUSD float64
	agents                  map[string]AgentPolicy
}

// LoadPolicyRegistry reads a JSON file of financial policies.
func LoadPolicyRegistry(path string) (*PolicyRegistry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("finops: cannot read policies %s: %w", path, err)
	}

	var f policiesFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("finops: invalid JSON in %s: %w", path, err)
	}

	r := &PolicyRegistry{
		defaultDailyBudgetUSD:   f.DefaultDailyBudgetUSD,
		defaultMaxTokensPerTask: f.DefaultMaxTokensPerTask,
		defaultMaxCostPerReqUSD: f.DefaultMaxCostPerReqUSD,
		agents:                  make(map[string]AgentPolicy, len(f.Agents)),
	}
	for _, p := range f.Agents {
		if p.AgentID == "" {
			return nil, fmt.Errorf("finops: policy without agent_id in %s", path)
		}
		r.agents[p.AgentID] = p
	}
	return r, nil
}

// For returns an agent's policy: the explicit one, if it exists,
// otherwise one built from the registry's default values.
func (r *PolicyRegistry) For(agentID string) AgentPolicy {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if p, ok := r.agents[agentID]; ok {
		return effective(p)
	}
	return effective(AgentPolicy{
		AgentID:          agentID,
		DailyBudgetUSD:   r.defaultDailyBudgetUSD,
		MaxTokensPerTask: r.defaultMaxTokensPerTask,

		MaxCostPerRequestUSD: r.defaultMaxCostPerReqUSD,
	})
}

// Upsert adds or updates an agent's policy (used by the admin
// dashboard). The change is in-memory only — restarting the gateway
// reverts to the JSON file on disk.
func (r *PolicyRegistry) Upsert(p AgentPolicy) error {
	if p.AgentID == "" {
		return fmt.Errorf("finops: agent_id is required for a policy")
	}
	if p.DailyBudgetUSD < 0 || p.MaxTokensPerTask < 0 || p.MaxCostPerRequestUSD < 0 {
		return fmt.Errorf("finops: policy values cannot be negative")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.agents[p.AgentID] = p
	return nil
}

// DefaultMaxCostPerRequestUSD is the registry-wide configured default
// (0 if unset, in which case FallbackMaxCostPerRequestUSD applies).
func (r *PolicyRegistry) DefaultMaxCostPerRequestUSD() float64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.defaultMaxCostPerReqUSD
}

// All returns a copy of every explicit policy, plus the registry's
// current default values — used by the dashboard/API.
func (r *PolicyRegistry) All() (defaults AgentPolicy, agents []AgentPolicy) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	defaults = AgentPolicy{DailyBudgetUSD: r.defaultDailyBudgetUSD, MaxTokensPerTask: r.defaultMaxTokensPerTask, MaxCostPerRequestUSD: r.defaultMaxCostPerReqUSD}
	agents = make([]AgentPolicy, 0, len(r.agents))
	for _, p := range r.agents {
		agents = append(agents, p)
	}
	return defaults, agents
}
