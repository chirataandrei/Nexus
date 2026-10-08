#!/usr/bin/env bash
# ~60-second end-to-end demo: identity -> allowed call -> budget cut-off
# -> kill switch -> revocation -> tamper-evident ledger. Everything runs
# locally against a fake upstream, in a throwaway temp directory.
set -euo pipefail
cd "$(dirname "$0")/.."

W=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$W"' EXIT
GW=http://127.0.0.1:8088
say() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; sleep "${DEMO_PAUSE:-1}"; }
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

go build -o "$W/gw" ./cmd/nexus-gateway
go build -o "$W/ctl" ./cmd/nexus-agentctl
go build -o "$W/up" ./cmd/nexus-demo-upstream

ADMIN=$("$W/ctl" -gen-admin-token)
ADMIN_TOKEN=$(echo "$ADMIN" | sed -n 's/^admin token[^:]*: //p')
ADMIN_HASH=$(echo "$ADMIN" | sed -n 's/.*"admin_token_sha256": "\(.*\)"/\1/p')
SECRET=demo-secret-$RANDOM
ENTRY=$("$W/ctl" -agent-id demo-agent -secret "$SECRET" -scopes "llm:demo:invoke" 2>/dev/null | sed '1d')

cat > "$W/agents.json" <<JSON
{"default_max_ttl_seconds":300,"agents":[$ENTRY]}
JSON
# Budget $0.05/day; each call is 1000 tokens at $0.01/1k = $0.01.
cat > "$W/finops.json" <<JSON
{"default_daily_budget_usd":0.05,"default_max_cost_per_request_usd":0.01,"default_max_tokens_per_task":100000}
JSON
cat > "$W/config.json" <<JSON
{"listen_addr":"127.0.0.1:8088","max_body_bytes":1048576,"trust_domain":"demo.trust",
 "agents_file":"$W/agents.json","identity_key_file":"$W/identity.key.json","admin_token_sha256":"$ADMIN_HASH",
 "finops_policies_file":"$W/finops.json","compliance_ledger_file":"$W/ledger.jsonl","compliance_retention_months":6,
 "compliance_anchor_file":"$W/anchors.jsonl","compliance_anchor_key_file":"$W/anchor.key.json","compliance_anchor_every_records":5,
 "upstreams":[{"name":"llm","path_prefix":"/v1/llm","target_url":"http://127.0.0.1:9101","strip_prefix":true,
   "required_scope":"llm:demo:invoke","price_per_1k_tokens_usd":0.01}]}
JSON

"$W/up" & "$W/gw" -config "$W/config.json" >"$W/gw.log" 2>&1 &
for _ in $(seq 50); do curl -s "$GW/nexus/control/suspended" >/dev/null 2>&1 && break; sleep 0.1; done

say "1. A request with no identity is rejected"
echo "HTTP $(code -X POST "$GW/v1/llm/chat" -d '{}')   (expected 401)"

say "2. The agent trades its bootstrap secret for a 5-minute JWT-SVID"
TOKEN=$(curl -s -X POST "$GW/nexus/identity/token" -d "{\"agent_id\":\"demo-agent\",\"secret\":\"$SECRET\",\"task_id\":\"task-1\"}" | sed 's/.*"token":"\([^"]*\)".*/\1/')
echo "token: ${TOKEN:0:40}…"

say "3. Calls within budget go through (each costs \$0.01, budget \$0.05)"
for i in 1 2 3 4 5; do echo "call $i -> HTTP $(code -X POST "$GW/v1/llm/chat" -H "Authorization: Bearer $TOKEN" -d '{}')"; done

say "4. The 6th call is stopped by the budget circuit breaker"
echo "call 6 -> HTTP $(code -X POST "$GW/v1/llm/chat" -H "Authorization: Bearer $TOKEN" -d '{}')   (expected 429)"

say "5. Kill switch: an operator suspends the agent (needs the admin token)"
echo "without admin token -> HTTP $(code -X POST "$GW/nexus/control/suspend" -d '{"agent_id":"demo-agent","reason":"demo"}')   (expected 401)"
echo "with admin token    -> HTTP $(code -X POST "$GW/nexus/control/suspend" -H "Authorization: Bearer $ADMIN_TOKEN" -d '{"agent_id":"demo-agent","reason":"abnormal behaviour","operator":"demo"}')"
echo "existing token now  -> HTTP $(code -X POST "$GW/v1/llm/chat" -H "Authorization: Bearer $TOKEN" -d '{}')   (expected 401)"
NEWTOK="{\"agent_id\":\"demo-agent\",\"secret\":\"$SECRET\",\"task_id\":\"t2\"}"
echo "new token request   -> HTTP $(code -X POST "$GW/nexus/identity/token" -d "$NEWTOK")   (expected 403)"

say "6. Every decision is in the hash-chained, signed-anchored ledger"
curl -s "$GW/nexus/compliance/verify"; echo
echo "last records:"; tail -n 3 "$W/ledger.jsonl" | sed 's/"prompt_excerpt":"[^"]*",//' | cut -c1-200
