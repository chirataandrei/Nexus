// handler.go expune API-ul de administrare FinOps și un dashboard HTML
// minimal (fără build step, fără dependențe JS externe) prin care un
// administrator vede consumul curent al fiecărui agent și poate ajusta
// politicile de buget la runtime.
package finops

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
)

const maxPolicyRequestBytes = 1 << 16 // 64 KiB

// UsageEntry combină politica unui agent cu consumul lui curent, pentru
// a fi afișat direct într-un tabel de dashboard.
type UsageEntry struct {
	AgentID          string         `json:"agent_id"`
	DailyBudgetUSD   float64        `json:"daily_budget_usd"`
	MaxTokensPerTask int            `json:"max_tokens_per_task"`
	SpentUSDToday    float64        `json:"spent_usd_today"`
	Date             string         `json:"date,omitempty"`
	TaskTokens       map[string]int `json:"task_tokens,omitempty"`
}

// UsageHandler expune GET /nexus/finops/usage: o listă cu toți agenții
// care au o politică explicită și/sau au generat deja consum astăzi.
func UsageHandler(ledger *Ledger, policies *PolicyRegistry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "metodă neacceptată, folosiți GET", http.StatusMethodNotAllowed)
			return
		}

		snapshots := ledger.Snapshot()
		byAgent := make(map[string]AgentUsageSnapshot, len(snapshots))
		for _, s := range snapshots {
			byAgent[s.AgentID] = s
		}

		_, agentPolicies := policies.All()

		seen := make(map[string]bool, len(agentPolicies)+len(snapshots))
		entries := make([]UsageEntry, 0, len(agentPolicies)+len(snapshots))
		addEntry := func(agentID string) {
			if seen[agentID] {
				return
			}
			seen[agentID] = true
			p := policies.For(agentID)
			e := UsageEntry{AgentID: agentID, DailyBudgetUSD: p.DailyBudgetUSD, MaxTokensPerTask: p.MaxTokensPerTask}
			if s, ok := byAgent[agentID]; ok {
				e.SpentUSDToday = s.SpentUSD
				e.Date = s.Date
				e.TaskTokens = s.TaskTokens
			}
			entries = append(entries, e)
		}
		for _, p := range agentPolicies {
			addEntry(p.AgentID)
		}
		for _, s := range snapshots {
			addEntry(s.AgentID)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(entries)
	}
}

// policiesResponse este forma JSON returnată de GET /nexus/finops/policies.
type policiesResponse struct {
	Default AgentPolicy   `json:"default"`
	Agents  []AgentPolicy `json:"agents"`
}

// PoliciesHandler expune GET (citește politicile curente) și POST
// (creează/actualizează politica unui agent) pe /nexus/finops/policies.
func PoliciesHandler(policies *PolicyRegistry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			defaults, agents := policies.All()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(policiesResponse{Default: defaults, Agents: agents})

		case http.MethodPost:
			var p AgentPolicy
			dec := json.NewDecoder(io.LimitReader(r.Body, maxPolicyRequestBytes))
			if err := dec.Decode(&p); err != nil {
				http.Error(w, "corp JSON invalid", http.StatusBadRequest)
				return
			}
			if err := policies.Upsert(p); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			slog.Info("nexus.finops.policy_updated",
				"event", "policy_updated",
				"agent_id", p.AgentID,
				"daily_budget_usd", p.DailyBudgetUSD,
				"max_tokens_per_task", p.MaxTokensPerTask,
			)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(p)

		default:
			http.Error(w, "metodă neacceptată, folosiți GET sau POST", http.StatusMethodNotAllowed)
		}
	}
}

// DashboardHandler expune GET /nexus/finops/dashboard: o pagină HTML
// auto-conținută (CSS+JS inline, fără build step) care citește
// /nexus/finops/usage și /nexus/finops/policies și permite actualizarea
// bugetului unui agent direct din browser.
func DashboardHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "metodă neacceptată, folosiți GET", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(dashboardHTML))
	}
}

const dashboardHTML = `<!doctype html>
<html lang="ro">
<head>
<meta charset="utf-8">
<title>Nexus Trust Protocol — FinOps</title>
<style>
  body { font-family: -apple-system, system-ui, sans-serif; margin: 2rem; background:#0b1220; color:#e6e9ef; }
  h1 { font-size: 1.3rem; margin-bottom: 0.2rem; }
  p.sub { color:#8d97ab; margin-top:0; }
  table { width:100%; border-collapse: collapse; margin-top:1.2rem; }
  th, td { text-align:left; padding:0.5rem 0.7rem; border-bottom:1px solid #1f2937; font-size:0.9rem; }
  th { color:#8d97ab; font-weight:600; text-transform:uppercase; font-size:0.72rem; letter-spacing:0.04em; }
  .over { color:#ff6b6b; font-weight:600; }
  .ok { color:#4ade80; }
  form { margin-top:2rem; display:flex; gap:0.6rem; flex-wrap:wrap; align-items:flex-end; }
  label { display:flex; flex-direction:column; font-size:0.78rem; color:#8d97ab; gap:0.25rem; }
  input { background:#111827; border:1px solid #1f2937; color:#e6e9ef; padding:0.4rem 0.5rem; border-radius:6px; }
  button { background:#3b82f6; border:none; color:white; padding:0.5rem 0.9rem; border-radius:6px; cursor:pointer; font-size:0.85rem; }
  button:hover { background:#2563eb; }
  #status { margin-top:0.6rem; font-size:0.85rem; color:#8d97ab; }
</style>
</head>
<body>
  <h1>Nexus Trust Protocol — FinOps</h1>
  <p class="sub">Consum curent per agent (resetat zilnic, UTC) și politici de buget.</p>

  <table id="usage-table">
    <thead>
      <tr><th>Agent</th><th>Cheltuit azi</th><th>Buget zilnic</th><th>Sarcini active</th></tr>
    </thead>
    <tbody></tbody>
  </table>

  <form id="policy-form">
    <label>Agent ID <input name="agent_id" required></label>
    <label>Buget zilnic (USD) <input name="daily_budget_usd" type="number" step="0.01" min="0" required></label>
    <label>Max tokeni / sarcină <input name="max_tokens_per_task" type="number" step="1" min="0" required></label>
    <button type="submit">Salvează politica</button>
  </form>
  <div id="status"></div>

<script>
async function loadUsage() {
  const res = await fetch('/nexus/finops/usage');
  const rows = await res.json();
  const tbody = document.querySelector('#usage-table tbody');
  tbody.innerHTML = '';
  for (const row of rows) {
    const tr = document.createElement('tr');
    const over = row.daily_budget_usd > 0 && row.spent_usd_today >= row.daily_budget_usd;
    const tasks = row.task_tokens ? Object.entries(row.task_tokens).map(([t, n]) => t + ': ' + n + ' tok').join(', ') : '—';
    tr.innerHTML =
      '<td>' + row.agent_id + '</td>' +
      '<td class="' + (over ? 'over' : 'ok') + '">$' + row.spent_usd_today.toFixed(4) + '</td>' +
      '<td>' + (row.daily_budget_usd > 0 ? '$' + row.daily_budget_usd.toFixed(2) : 'nelimitat') + '</td>' +
      '<td>' + tasks + '</td>';
    tbody.appendChild(tr);
  }
}

document.getElementById('policy-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const form = ev.target;
  const payload = {
    agent_id: form.agent_id.value,
    daily_budget_usd: parseFloat(form.daily_budget_usd.value),
    max_tokens_per_task: parseInt(form.max_tokens_per_task.value, 10),
  };
  const res = await fetch('/nexus/finops/policies', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) });
  const statusEl = document.getElementById('status');
  if (res.ok) {
    statusEl.textContent = 'Politică salvată pentru ' + payload.agent_id + '.';
    await loadUsage();
  } else {
    statusEl.textContent = 'Eroare: ' + await res.text();
  }
});

loadUsage();
setInterval(loadUsage, 5000);
</script>
</body>
</html>
`
