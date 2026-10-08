// handler.go exposes the FinOps admin API and a minimal HTML dashboard
// (no build step, no external JS dependencies) through which an
// administrator sees each agent's current consumption and can adjust
// budget policies at runtime.
package finops

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
)

const maxPolicyRequestBytes = 1 << 16 // 64 KiB

// UsageEntry combines an agent's policy with its current consumption,
// meant to be displayed directly in a dashboard table.
type UsageEntry struct {
	AgentID          string         `json:"agent_id"`
	DailyBudgetUSD   float64        `json:"daily_budget_usd"`
	MaxTokensPerTask int            `json:"max_tokens_per_task"`
	SpentUSDToday    float64        `json:"spent_usd_today"`
	Date             string         `json:"date,omitempty"`
	TaskTokens       map[string]int `json:"task_tokens,omitempty"`
}

// UsageHandler exposes GET /nexus/finops/usage: a list of every agent
// that has an explicit policy and/or has already generated consumption
// today.
func UsageHandler(ledger *Ledger, policies *PolicyRegistry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed, use GET", http.StatusMethodNotAllowed)
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

// policiesResponse is the JSON shape returned by GET /nexus/finops/policies.
type policiesResponse struct {
	Default AgentPolicy   `json:"default"`
	Agents  []AgentPolicy `json:"agents"`
}

// PoliciesHandler exposes GET (reads current policies) and POST
// (creates/updates an agent's policy) on /nexus/finops/policies.
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
				http.Error(w, "invalid JSON body", http.StatusBadRequest)
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
			http.Error(w, "method not allowed, use GET or POST", http.StatusMethodNotAllowed)
		}
	}
}

// DashboardHandler exposes GET /nexus/finops/dashboard: a self-contained
// HTML page (inline CSS+JS, no build step) that reads
// /nexus/finops/usage and /nexus/finops/policies and lets you update an
// agent's budget directly from the browser.
func DashboardHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed, use GET", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(dashboardHTML))
	}
}

const dashboardHTML = `<!doctype html>
<html lang="en">
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
  <p class="sub">Current consumption per agent (reset daily, UTC) and budget policies.</p>
  <label>Admin token <input id="token" type="password" autocomplete="off" placeholder="paste the admin token"></label>

  <table id="usage-table">
    <thead>
      <tr><th>Agent</th><th>Spent today</th><th>Daily budget</th><th>Active tasks</th></tr>
    </thead>
    <tbody></tbody>
  </table>

  <form id="policy-form">
    <label>Agent ID <input name="agent_id" required></label>
    <label>Daily budget (USD) <input name="daily_budget_usd" type="number" step="0.01" min="0" required></label>
    <label>Max tokens / task <input name="max_tokens_per_task" type="number" step="1" min="0" required></label>
    <label>Max cost / request (USD, blank = default) <input name="max_cost_per_request_usd" type="number" step="0.0001" min="0"></label>
    <button type="submit">Save policy</button>
  </form>
  <div id="status"></div>

<script>
const tokenInput = document.getElementById('token');
try { tokenInput.value = sessionStorage.getItem('nexusAdminToken') || ''; } catch (e) {}
tokenInput.addEventListener('change', () => {
  try { sessionStorage.setItem('nexusAdminToken', tokenInput.value); } catch (e) {}
  loadUsage();
});
function authHeaders(extra) {
  const h = Object.assign({}, extra || {});
  if (tokenInput.value) h['Authorization'] = 'Bearer ' + tokenInput.value;
  return h;
}

async function loadUsage() {
  const res = await fetch('/nexus/finops/usage', { headers: authHeaders() });
  const statusEl = document.getElementById('status');
  if (!res.ok) {
    statusEl.textContent = res.status === 401 ? 'Enter the admin token to see usage.' : 'Error: ' + await res.text();
    return;
  }
  const rows = await res.json();
  const tbody = document.querySelector('#usage-table tbody');
  tbody.innerHTML = '';
  for (const row of rows) {
    const tr = document.createElement('tr');
    const over = row.daily_budget_usd > 0 && row.spent_usd_today >= row.daily_budget_usd;
    const tasks = row.task_tokens ? Object.entries(row.task_tokens).map(([t, n]) => t + ': ' + n + ' tok').join(', ') : '—';
    const cells = [
      [row.agent_id, ''],
      ['$' + row.spent_usd_today.toFixed(4), over ? 'over' : 'ok'],
      [row.daily_budget_usd > 0 ? '$' + row.daily_budget_usd.toFixed(2) : 'unlimited', ''],
      [tasks, ''],
    ];
    for (const [text, cls] of cells) { // textContent: agent/task IDs are not trusted HTML
      const td = document.createElement('td');
      td.textContent = text;
      if (cls) td.className = cls;
      tr.appendChild(td);
    }
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
    max_cost_per_request_usd: form.max_cost_per_request_usd.value ? parseFloat(form.max_cost_per_request_usd.value) : 0,
  };
  const res = await fetch('/nexus/finops/policies', { method: 'POST', headers: authHeaders({'Content-Type':'application/json'}), body: JSON.stringify(payload) });
  const statusEl = document.getElementById('status');
  if (res.ok) {
    statusEl.textContent = 'Policy saved for ' + payload.agent_id + '.';
    await loadUsage();
  } else {
    statusEl.textContent = 'Error: ' + await res.text();
  }
});

loadUsage();
setInterval(loadUsage, 5000);
</script>
</body>
</html>
`
