package finops

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestPolicyRegistry(t *testing.T) *PolicyRegistry {
	t.Helper()
	path := writeTempPoliciesFile(t, `{
		"default_daily_budget_usd": 1.0,
		"default_max_tokens_per_task": 1000,
		"agents": [{"agent_id": "agent-1", "daily_budget_usd": 5.0, "max_tokens_per_task": 20000}]
	}`)
	reg, err := LoadPolicyRegistry(path)
	if err != nil {
		t.Fatalf("LoadPolicyRegistry a eșuat: %v", err)
	}
	return reg
}

func TestUsageHandler_CombinesPoliciesAndLedger(t *testing.T) {
	policies := newTestPolicyRegistry(t)
	ledger := NewLedger()
	ledger.RecordSpend("agent-1", "task-1", 1500, 1.5)

	handler := UsageHandler(ledger, policies)
	req := httptest.NewRequest(http.MethodGet, "/nexus/finops/usage", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var entries []UsageEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &entries); err != nil {
		t.Fatalf("răspuns JSON invalid: %v", err)
	}

	var found *UsageEntry
	for i := range entries {
		if entries[i].AgentID == "agent-1" {
			found = &entries[i]
		}
	}
	if found == nil {
		t.Fatal("ar trebui să existe o intrare pentru agent-1")
	}
	if found.DailyBudgetUSD != 5.0 {
		t.Errorf("daily_budget_usd = %v, vroiam 5.0", found.DailyBudgetUSD)
	}
	if found.SpentUSDToday != 1.5 {
		t.Errorf("spent_usd_today = %v, vroiam 1.5", found.SpentUSDToday)
	}
	if found.TaskTokens["task-1"] != 1500 {
		t.Errorf("task_tokens[task-1] = %v, vroiam 1500", found.TaskTokens["task-1"])
	}
}

func TestUsageHandler_RejectsNonGET(t *testing.T) {
	handler := UsageHandler(NewLedger(), newTestPolicyRegistry(t))
	req := httptest.NewRequest(http.MethodPost, "/nexus/finops/usage", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, vroiam 405", rec.Code)
	}
}

func TestPoliciesHandler_GetReturnsDefaultsAndAgents(t *testing.T) {
	policies := newTestPolicyRegistry(t)
	handler := PoliciesHandler(policies)

	req := httptest.NewRequest(http.MethodGet, "/nexus/finops/policies", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	var resp policiesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("răspuns JSON invalid: %v", err)
	}
	if resp.Default.DailyBudgetUSD != 1.0 {
		t.Errorf("default daily_budget_usd = %v, vroiam 1.0", resp.Default.DailyBudgetUSD)
	}
	if len(resp.Agents) != 1 || resp.Agents[0].AgentID != "agent-1" {
		t.Errorf("agenți greșiți în răspuns: %+v", resp.Agents)
	}
}

func TestPoliciesHandler_PostUpsertsPolicy(t *testing.T) {
	policies := newTestPolicyRegistry(t)
	handler := PoliciesHandler(policies)

	payload, _ := json.Marshal(AgentPolicy{AgentID: "agent-2", DailyBudgetUSD: 10, MaxTokensPerTask: 5000})
	req := httptest.NewRequest(http.MethodPost, "/nexus/finops/policies", bytes.NewReader(payload))
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if got := policies.For("agent-2"); got.DailyBudgetUSD != 10 {
		t.Errorf("policy nu a fost salvată: %+v", got)
	}
}

func TestPoliciesHandler_PostRejectsMissingAgentID(t *testing.T) {
	policies := newTestPolicyRegistry(t)
	handler := PoliciesHandler(policies)

	payload, _ := json.Marshal(AgentPolicy{DailyBudgetUSD: 10})
	req := httptest.NewRequest(http.MethodPost, "/nexus/finops/policies", bytes.NewReader(payload))
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, vroiam 400", rec.Code)
	}
}

func TestDashboardHandler_ServesHTML(t *testing.T) {
	handler := DashboardHandler()
	req := httptest.NewRequest(http.MethodGet, "/nexus/finops/dashboard", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("Nexus Trust Protocol")) {
		t.Error("pagina HTML ar trebui să conțină titlul dashboard-ului")
	}
}
