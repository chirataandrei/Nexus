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
		t.Fatalf("cannot write temp file: %v", err)
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
		t.Fatalf("LoadPolicyRegistry failed: %v", err)
	}

	p1 := reg.For("agent-1")
	if p1.DailyBudgetUSD != 5.0 || p1.MaxTokensPerTask != 20000 {
		t.Errorf("explicit policy read incorrectly: %+v", p1)
	}

	p2 := reg.For("unknown-agent")
	if p2.DailyBudgetUSD != 2.5 || p2.MaxTokensPerTask != 10000 {
		t.Errorf("the default policy should apply to an agent without its own policy: %+v", p2)
	}
}

func TestPolicyRegistry_Upsert(t *testing.T) {
	path := writeTempPoliciesFile(t, `{"agents": []}`)
	reg, err := LoadPolicyRegistry(path)
	if err != nil {
		t.Fatalf("LoadPolicyRegistry failed: %v", err)
	}

	if err := reg.Upsert(AgentPolicy{AgentID: "new-agent", DailyBudgetUSD: 3.0}); err != nil {
		t.Fatalf("Upsert failed: %v", err)
	}
	got := reg.For("new-agent")
	if got.DailyBudgetUSD != 3.0 {
		t.Errorf("Upsert wasn't reflected: %+v", got)
	}
}

func TestPolicyRegistry_UpsertRejectsInvalid(t *testing.T) {
	path := writeTempPoliciesFile(t, `{"agents": []}`)
	reg, err := LoadPolicyRegistry(path)
	if err != nil {
		t.Fatalf("LoadPolicyRegistry failed: %v", err)
	}

	if err := reg.Upsert(AgentPolicy{AgentID: ""}); err == nil {
		t.Error("Upsert should reject a policy without agent_id")
	}
	if err := reg.Upsert(AgentPolicy{AgentID: "x", DailyBudgetUSD: -1}); err == nil {
		t.Error("Upsert should reject a negative budget")
	}
}

func TestLoadPolicyRegistry_RejectsMissingAgentID(t *testing.T) {
	path := writeTempPoliciesFile(t, `{"agents": [{"daily_budget_usd": 1.0}]}`)
	if _, err := LoadPolicyRegistry(path); err == nil {
		t.Error("LoadPolicyRegistry should reject a policy without agent_id")
	}
}
