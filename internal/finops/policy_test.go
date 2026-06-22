package finops

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempPoliciesFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "finops_policies.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("nu pot scrie fișierul temporar: %v", err)
	}
	return path
}

func TestLoadPolicyRegistry_ValidFile(t *testing.T) {
	path := writeTempPoliciesFile(t, `{
		"default_daily_budget_usd": 2.5,
		"default_max_tokens_per_task": 10000,
		"agents": [
			{"agent_id": "agent-1", "daily_budget_usd": 5.0, "max_tokens_per_task": 20000}
		]
	}`)

	reg, err := LoadPolicyRegistry(path)
	if err != nil {
		t.Fatalf("LoadPolicyRegistry a eșuat: %v", err)
	}

	p1 := reg.For("agent-1")
	if p1.DailyBudgetUSD != 5.0 || p1.MaxTokensPerTask != 20000 {
		t.Errorf("politica explicită citită greșit: %+v", p1)
	}

	p2 := reg.For("agent-necunoscut")
	if p2.DailyBudgetUSD != 2.5 || p2.MaxTokensPerTask != 10000 {
		t.Errorf("politica implicită ar trebui aplicată unui agent fără politică proprie: %+v", p2)
	}
}

func TestPolicyRegistry_Upsert(t *testing.T) {
	path := writeTempPoliciesFile(t, `{"agents": []}`)
	reg, err := LoadPolicyRegistry(path)
	if err != nil {
		t.Fatalf("LoadPolicyRegistry a eșuat: %v", err)
	}

	if err := reg.Upsert(AgentPolicy{AgentID: "agent-nou", DailyBudgetUSD: 3.0}); err != nil {
		t.Fatalf("Upsert a eșuat: %v", err)
	}
	got := reg.For("agent-nou")
	if got.DailyBudgetUSD != 3.0 {
		t.Errorf("Upsert nu a fost reflectat: %+v", got)
	}
}

func TestPolicyRegistry_UpsertRejectsInvalid(t *testing.T) {
	path := writeTempPoliciesFile(t, `{"agents": []}`)
	reg, err := LoadPolicyRegistry(path)
	if err != nil {
		t.Fatalf("LoadPolicyRegistry a eșuat: %v", err)
	}

	if err := reg.Upsert(AgentPolicy{AgentID: ""}); err == nil {
		t.Error("Upsert ar trebui să respingă o politică fără agent_id")
	}
	if err := reg.Upsert(AgentPolicy{AgentID: "x", DailyBudgetUSD: -1}); err == nil {
		t.Error("Upsert ar trebui să respingă un buget negativ")
	}
}

func TestLoadPolicyRegistry_RejectsMissingAgentID(t *testing.T) {
	path := writeTempPoliciesFile(t, `{"agents": [{"daily_budget_usd": 1.0}]}`)
	if _, err := LoadPolicyRegistry(path); err == nil {
		t.Error("LoadPolicyRegistry ar trebui să respingă o politică fără agent_id")
	}
}
