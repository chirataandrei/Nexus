// policy.go conține politicile financiare per agent: bugetul zilnic maxim
// (în USD) și limita de tokeni per sarcină. Acestea sunt definite de un
// administrator — implicit prin configs/finops_policies.json, dar
// modificabile la runtime prin dashboard (Upsert).
package finops

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// AgentPolicy descrie politica financiară a unui agent.
type AgentPolicy struct {
	AgentID string `json:"agent_id"`
	// DailyBudgetUSD este bugetul maxim pe care agentul îl poate cheltui
	// într-o zi calendaristică (UTC). 0 = fără limită de buget.
	DailyBudgetUSD float64 `json:"daily_budget_usd"`
	// MaxTokensPerTask este numărul maxim de tokeni pe care agentul îi
	// poate consuma într-o singură sarcină (task_id) — bariera directă
	// împotriva unei bucle de halucinație recurentă. 0 = fără limită.
	MaxTokensPerTask int `json:"max_tokens_per_task"`
}

// policiesFile este formatul JSON de pe disc.
type policiesFile struct {
	DefaultDailyBudgetUSD   float64       `json:"default_daily_budget_usd"`
	DefaultMaxTokensPerTask int           `json:"default_max_tokens_per_task"`
	Agents                  []AgentPolicy `json:"agents"`
}

// PolicyRegistry ține politicile per agent, plus valorile implicite
// folosite pentru orice agent fără o intrare explicită.
type PolicyRegistry struct {
	mu                      sync.RWMutex
	defaultDailyBudgetUSD   float64
	defaultMaxTokensPerTask int
	agents                  map[string]AgentPolicy
}

// LoadPolicyRegistry citește un fișier JSON de politici financiare.
func LoadPolicyRegistry(path string) (*PolicyRegistry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("finops: nu pot citi politicile %s: %w", path, err)
	}

	var f policiesFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("finops: JSON invalid în %s: %w", path, err)
	}

	r := &PolicyRegistry{
		defaultDailyBudgetUSD:   f.DefaultDailyBudgetUSD,
		defaultMaxTokensPerTask: f.DefaultMaxTokensPerTask,
		agents:                  make(map[string]AgentPolicy, len(f.Agents)),
	}
	for _, p := range f.Agents {
		if p.AgentID == "" {
			return nil, fmt.Errorf("finops: politică fără agent_id în %s", path)
		}
		r.agents[p.AgentID] = p
	}
	return r, nil
}

// For returnează politica unui agent: cea explicită, dacă există, altfel
// una construită din valorile implicite ale registrului.
func (r *PolicyRegistry) For(agentID string) AgentPolicy {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if p, ok := r.agents[agentID]; ok {
		return p
	}
	return AgentPolicy{
		AgentID:          agentID,
		DailyBudgetUSD:   r.defaultDailyBudgetUSD,
		MaxTokensPerTask: r.defaultMaxTokensPerTask,
	}
}

// Upsert adaugă sau actualizează politica unui agent (folosit de
// dashboard-ul de administrare). Modificarea este doar în memorie —
// un restart al gateway-ului revine la fișierul JSON de pe disc.
func (r *PolicyRegistry) Upsert(p AgentPolicy) error {
	if p.AgentID == "" {
		return fmt.Errorf("finops: agent_id este obligatoriu pentru o politică")
	}
	if p.DailyBudgetUSD < 0 || p.MaxTokensPerTask < 0 {
		return fmt.Errorf("finops: valorile politicii nu pot fi negative")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.agents[p.AgentID] = p
	return nil
}

// All returnează o copie a tuturor politicilor explicite, plus valorile
// implicite curente ale registrului — folosit de dashboard/API.
func (r *PolicyRegistry) All() (defaults AgentPolicy, agents []AgentPolicy) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	defaults = AgentPolicy{DailyBudgetUSD: r.defaultDailyBudgetUSD, MaxTokensPerTask: r.defaultMaxTokensPerTask}
	agents = make([]AgentPolicy, 0, len(r.agents))
	for _, p := range r.agents {
		agents = append(agents, p)
	}
	return defaults, agents
}
