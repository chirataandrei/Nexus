# Nexus Trust Protocol — Gateway

[![CI](https://github.com/chirataandrei/Nexus/actions/workflows/ci.yml/badge.svg)](https://github.com/chirataandrei/Nexus/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/chirataandrei/Nexus/sdk.svg)](https://pkg.go.dev/github.com/chirataandrei/Nexus/sdk)

A Layer 7 reverse proxy written in Go (standard library only, no external dependencies) that sits between AI agents and LLM models / internal services. It eliminates static API keys (each agent gets an ephemeral cryptographic identity, inspired by WIMSE/SPIFFE), enforces real-time per-agent budgets, writes every request to a tamper-evident ledger, and recognizes Model Context Protocol (MCP) traffic and enforces per-tool scopes on it.

## Project structure

```
./                     repository root
  go.work               Go workspace: links the gateway module to the sdk module
  cmd/nexus-gateway/    entry point (main.go)
  cmd/nexus-agentctl/   dev utility: secret_hash for agents.json, admin token, key inspection
  cmd/nexus-bench/      latency/throughput benchmark (make bench)
  cmd/nexus-demo-upstream/  fake LLM used by scripts/demo.sh
  scripts/demo.sh       60-second end-to-end demo (make demo)
  internal/keystore/    persisted Ed25519 keys + kid (identity, ledger anchors)
  internal/admin/       admin-token auth for the operator endpoints
  internal/config/      configuration loading and validation (JSON)
  internal/parser/      REST/JSON-RPC/MCP detection, metadata extraction
  internal/mcp/         MCP method recognition, tool name extraction
  internal/proxy/       path-prefix routing + extension hooks
  internal/logging/     structured logging (stdout, JSON) + Fanout
  internal/identity/    AIMS — JWT-SVID, agent registry, validator
  internal/finops/      cost ledger, budget policies, dashboard
  internal/compliance/  tamper-evident WORM chain, kill switch
  sdk/                  Go client SDK, a separate Go module (sdk/go.mod)
    examples/basic/      example use of the SDK
  docs/MCP.md           how MCP compatibility + per-tool scopes work
  docs/THREAT_MODEL.md  assets, attackers, mitigations, residual risks
  data/                              compliance chain (generated at runtime, git-ignored)
  configs/config.json                example gateway configuration
  configs/agents.json                 example agent registry
  configs/finops_policies.json        example budget policies
```

## Routing and protocols

`internal/parser` intercepts HTTP/REST and JSON-RPC requests based on a per-upstream path prefix, and `internal/proxy` routes them to the right upstream (external LLM model or internal service), with "strip prefix" support. Every request is logged in a structured way (JSON on stdout): HTTP method, path, detected protocol, JSON-RPC method, duration, status code. Sensitive headers (`Authorization`, `X-Api-Key`, `Cookie`) are automatically masked.

Beyond generic JSON-RPC, the gateway explicitly recognizes the Model Context Protocol vocabulary (`tools/call`, `tools/list`, `resources/*`, `prompts/*`, `notifications/*`) — `RequestMeta.Protocol` becomes `"MCP"` instead of the generic `"JSON-RPC"`, and for `tools/call`, the exact name of the tool being called is extracted into `RequestMeta.MCPTool`. Details: [`docs/MCP.md`](docs/MCP.md).

## Identity (AIMS — Agent Identity Management System)

No long-lived secret ever travels to the upstreams. An agent does a one-time "bootstrap": it sends `agent_id` + a pre-distributed secret to `POST /nexus/identity/token` and gets back a **JWT-SVID** — an Ed25519-signed token, strictly tied to an `agent_id` + `task_id` + an explicit set of `scopes`, valid for 5 minutes by default. Every token has a `sub` of the form `spiffe://<trust_domain>/agent/<agent_id>/task/<task_id>`.

`internal/identity.SPIFFEValidator` automatically rejects any request without an `Authorization: Bearer <token>` header, with an invalid or expired signature, from a different trust domain, or without the scope the route explicitly requires. The agent registry (`configs/agents.json`) defines `allowed_scopes` per agent — any requested scope not in `allowed_scopes` is rejected with `403` (anti-privilege-escalation). `parser.RequestMeta` distinguishes `AgentID` (an unsafe header, debugging only) from `VerifiedAgentID`/`SPIFFEID`/`VerifiedScopes` (populated only after a successful cryptographic check).

**Token lifecycle and abuse resistance** (details and residual risks in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)):

- *Persisted key, rotation.* The signing key lives in `identity_key_file` (mode 0600, created on first start), so tokens survive restarts. Every token carries a `kid`; to rotate, replace the key file and list the old public key (`nexus-agentctl -show-pubkey <old key file>`) in `identity_retired_keys_file` until old tokens expire. An unknown `kid` is rejected.
- *Stolen token.* A token is a bearer credential: whoever holds it can use it until `exp` (5 min by default) — or until an operator revokes it. Every token has a unique `jti`, recorded in the ledger on each request; `POST /nexus/control/revoke {"jti": ...}` blocks that one token immediately, and `POST /nexus/control/suspend` blocks the whole agent. Scopes are least-privilege and tokens are bound to one `task_id`.
- *Brute force on `/nexus/identity/token`.* Failed attempts are limited per client IP (20/min) and per agent+IP (5/min) with `429` + `Retry-After`; unknown agents count as failures too, so enumeration is limited. Secrets are stored as salted **PBKDF2-HMAC-SHA256** (600k iterations, `pbkdf2-sha256$...`), compared in constant time, and an unknown agent costs the same work as a wrong secret. Legacy bare-sha256 entries still load but log a warning.
- *Operator endpoints* (`/nexus/control/*`, `/nexus/finops/policies`) require `Authorization: Bearer <admin token>`; only its SHA-256 is in the config (`nexus-agentctl -gen-admin-token`).

Different tools behind the same MCP upstream can require different permissions: `config.Upstream.ToolScopes` (a `tool_name -> scope` map) lets, for example, `read_email` require `tools:email:read` and `delete_email` require `tools:email:delete`, even though both go through the same upstream.

## Budget (the FinOps router)

Before a request reaches the LLM, `internal/finops.Enforcer` checks the in-memory `Ledger` to see whether the agent has already exhausted its daily budget or the current task's token limit — if so, the request is rejected with `429`, without consuming a single costly token. `internal/finops.Recorder` reads `usage` from the LLM's response (OpenAI/Anthropic) through the reverse proxy's `ModifyResponse`, and updates the ledger without altering the response sent to the agent. `max_tokens_per_task` caps the tokens accumulated within a single task, no matter how many separate requests the agent makes — a direct circuit breaker against recurring hallucination loops.

A simple dashboard is available at `GET /nexus/finops/dashboard`, plus an API at `/nexus/finops/usage` and `/nexus/finops/policies`. Both need the admin token (paste it into the dashboard's token field); set `public_usage_endpoint: true` only if `/usage` must be readable without one.

## Compliance and kill switch

Every request generates a record in `internal/compliance.Chain`, which includes its own hash and the hash of the previous record — a local mini-blockchain, written strictly by appending, durable (`fsync`) before each write returns. Concurrent writers share one `fsync` (group commit), so the guarantee per record is unchanged while the number of syncs drops under load. Any retroactive change (editing, deleting, reordering) breaks the hash chain and is detectable: `OpenChain` fully re-verifies the existing chain at startup, and if it was modified outside the gateway, startup is refused.

`internal/compliance.Sink` logs, for every request: the verified identity *and* the claimed one, the tool/upstream called, the final decision, status, duration, today's cumulative spend, and the prompt (full SHA-256 digest + a configurable, truncated readable excerpt). The minimum 6-month retention is enforced at the configuration level.

**Tamper evidence, and what it does not cover.** A hash chain alone cannot survive someone who rewrites the whole file: they can edit a record and recompute every hash after it, and the chain still verifies. So the head of the chain is periodically **signed with an Ed25519 anchor key** (`compliance_anchor_key_file`, separate from the identity key) and appended to a separate anchors file (`compliance_anchor_file` — put it on another volume; each anchor is also logged on stdout so a log shipper keeps a second copy). Anchors are chained to each other and carry a `kid`. At startup, and on `GET /nexus/compliance/verify`, the ledger must match every anchor: an edited, rewritten, truncated or deleted ledger is detected, and the gateway refuses to start. The residual exposure is the interval since the last anchor (records after it are covered by the chain only), and an attacker who holds the anchor key or can wipe the ledger *and* the anchors file together; see the threat model.

**Fail-open vs. fail-closed.** If the ledger can't be written, by default (`compliance_fail_closed: true`, also when the key is omitted) the request is refused — completeness over availability. With `compliance_fail_closed: false` the error is logged and the request proceeds instead. In the default mode the request record is written *before* forwarding and a failure returns `503` without contacting the upstream — no un-audited call can happen. Response/rejection records are written after the fact, so a failure there can only be logged.

An operator can instantly and globally suspend an agent: `POST /nexus/control/suspend|resume`, `GET /nexus/control/suspended` — requests using an already-issued token and the issuance of new tokens are both blocked immediately, and each action is itself recorded in the chain. `GET /nexus/compliance/verify` confirms the history's integrity at any time.

## SDK for developers

`sdk/` is a separate Go module (`go get github.com/chirataandrei/Nexus/sdk`, [docs on pkg.go.dev](https://pkg.go.dev/github.com/chirataandrei/Nexus/sdk), [release `sdk/v0.1.0`](https://github.com/chirataandrei/Nexus/releases/tag/sdk/v0.1.0)), with no dependency on the server's code (`internal/`), that automatically handles identity bootstrap, caching, and refreshing of the JWT-SVID token. It can plug into any existing SDK through a drop-in `*http.Client` (`client.HTTPClient()`). See [`sdk/README.md`](sdk/README.md) for installation and full examples, and `sdk/examples/basic` for a runnable program.

## Performance

`make bench` (`cmd/nexus-bench`) drives a fake local upstream directly and through the gateway with the same closed-loop load (50 concurrent workers, 10 s per scenario, JSON-RPC body, loopback, audit output discarded). Measured on an Apple Silicon laptop (client, gateway and upstream share the same machine, so absolute numbers are indicative):

| scenario | req/s | p50 | p95 | p99 |
|---|---|---|---|---|
| direct (no gateway) | 133k | 243 µs | 710 µs | 1.11 ms |
| gateway: proxy + parse | 75k | 566 µs | 1.42 ms | 1.89 ms |
| gateway: + FinOps budget/spend | 77k | 568 µs | 1.35 ms | 1.82 ms |

The first three rows discard audit records. The gateway itself adds roughly **0.3 ms at p50** and **under 1 ms at p99**.

With the real compliance ledger on (every request writes two records, each durable on disk before the request continues) the picture is very different, because the cost is the disk, not the CPU:

| scenario (FinOps + ledger `fsync`) | req/s | p50 | p99 |
|---|---|---|---|
| one `fsync` per record (before group commit), 50 workers | 129 | 387 ms | 435 ms |
| group commit, 10 workers | 485 | 20 ms | 29 ms |
| group commit, 50 workers | 713 | 70 ms | 113 ms |
| group commit, 200 workers | 1,173 | 152 ms | 330 ms |

Group commit made the ledger about 5.5× faster at 50 workers, and throughput keeps rising with concurrency because more records share each sync. It is still **disk-bound**: these numbers come from a MacBook, where Go's `File.Sync` issues `F_FULLFSYNC` (a real flush of the drive cache, ~10 ms) — Linux `fsync` on a server SSD is typically one to two orders of magnitude cheaper, so expect a much smaller gap there. Measure on your own hardware with `make bench`. If you cannot afford a durable write per request, the knob is the guarantee itself (not offered yet), not a faster benchmark.

The test suite runs under `go test -race` in CI, including a test that fires 500 simultaneous requests for one agent and asserts that exactly `daily_budget / max_cost_per_request` of them reach the upstream. That guarantee rests on reserving the worst-case cost of in-flight requests: set `max_cost_per_request_usd` (per agent, or `default_max_cost_per_request_usd`) to your real figure. If you don't, a budgeted agent reserves `min(daily budget, $1.00)` per request, so the budget still holds, at the price of fewer concurrent requests.

## Known limitations

- Suspensions and token revocations are replayed from the ledger at startup, so they survive a restart; they are only as durable as the ledger file itself. The identity key is a local file, not an HSM/SPIRE-managed key.
- A token is a bearer credential: it is not bound to a TLS channel or a client key (no DPoP/mTLS), so a stolen token works until `exp` or revocation.
- The gateway doesn't terminate TLS or trust `X-Forwarded-For`; run it behind a TLS proxy on a private network, and note per-IP limits then see the proxy's address unless it's the direct peer.
- Ledger records after the last signed anchor are protected by the hash chain only.
- The FinOps `Ledger` lives in a single process's memory — multiple Nexus instances running in parallel would need a shared store (e.g. Redis).
- The compliance chain is a single local file on a single instance; there's no automatic purging once retention expires.
- The non-custodial wallet integration (Locus, Skyfire) mentioned in the original proposal remains out of scope for now.
- MCP support is a recognizing proxy, not an MCP endpoint: it understands the message shapes and tool names, but doesn't implement the handshake or capability negotiation itself, and only the HTTP transports pass through (not stdio). It is tested against the official MCP Go SDK's real client and server over Streamable HTTP, including SSE responses (`make test-mcp`). JSON-RPC batch requests are rejected with `400` because per-tool scopes can only be enforced one call at a time.

## Demo

`make demo` (or `./scripts/demo.sh`) runs everything below against a fake upstream in a temp directory, in about a minute: a request with no identity is refused, the agent trades its secret for a JWT-SVID, five calls pass, the sixth hits the budget (`429`), an operator suspends the agent with the admin token (existing token and new-token requests are both refused), and the ledger verifies with its signed anchors.

## Running locally

Requires Go 1.22+.

```bash
go build ./...
go test ./... ./sdk/...     # gateway + sdk
go run ./cmd/nexus-gateway -config configs/config.json
```

`go.work` at the repository root links the two Go modules (the gateway itself and the client SDK) so commands like `go test ./... ./sdk/...` work from a single place, without the two being coupled at the code level — the SDK doesn't import anything from `internal/`.

By default, the gateway listens on `:8080`, the trust domain is `nexus.trust`, the compliance retention is 6 months, and it routes:

| Path prefix         | Upstream                     | Required scope             | Price / 1000 tokens |
|----------------------|-------------------------------|------------------------------|----------------------|
| `/v1/openai/...`     | `https://api.openai.com`      | `llm:openai:invoke`          | $0.01 |
| `/v1/anthropic/...`  | `https://api.anthropic.com`   | `llm:anthropic:invoke`       | $0.015 |
| `/v1/internal/...`   | `http://localhost:9000`       | `tools:internal:invoke` (or a per-tool scope, see `tool_scopes`) | $0 |

### 1. Register an agent and request a JWT-SVID

```bash
go run ./cmd/nexus-agentctl -agent-id agent-demo-1 -gen-secret -scopes "llm:openai:invoke"
# prints a generated secret once (stderr) and the PBKDF2 entry; use -secret "a-secret" to choose your own
# copy the result into configs/agents.json

TOKEN=$(curl -s -X POST http://localhost:8080/nexus/identity/token \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"agent-demo-1","secret":"a-secret","task_id":"task-1"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")

curl http://localhost:8080/v1/openai/models -H "Authorization: Bearer $TOKEN"
```

Or, equivalently, from Go code using the SDK (without managing the token yourself):

```go
client := nexussdk.New("http://localhost:8080", "agent-demo-1", "a-secret", "task-1")
resp, err := client.Do(req) // automatically attaches Authorization: Bearer <token>
```

### 2. Kill switch and token revocation

Operator endpoints need the admin token. Generate yours with `go run ./cmd/nexus-agentctl -gen-admin-token` and put the printed `admin_token_sha256` in `configs/config.json` (the committed value belongs to a throwaway token nobody has).

```bash
ADMIN="Authorization: Bearer <your admin token>"

curl -X POST http://localhost:8080/nexus/control/suspend -H "$ADMIN" \
  -d '{"agent_id":"agent-demo-1","reason":"abnormal behavior","operator":"andrei"}'

curl http://localhost:8080/nexus/control/suspended -H "$ADMIN"

curl -X POST http://localhost:8080/nexus/control/resume -H "$ADMIN" \
  -d '{"agent_id":"agent-demo-1","operator":"andrei"}'

# block one stolen token (its jti is in the ledger records) without suspending the agent
curl -X POST http://localhost:8080/nexus/control/revoke -H "$ADMIN" \
  -d '{"jti":"<jti>","reason":"token leaked","operator":"andrei"}'
```

### 3. Verify the compliance ledger's integrity

```bash
curl http://localhost:8080/nexus/compliance/verify
# {"ok": true, "verified_records": N, "verified_anchors": M}
```

### 4. FinOps dashboard

```
http://localhost:8080/nexus/finops/dashboard
```

## Tests

Fuzz targets (`go test -fuzz=FuzzParse ./internal/parser`, `-fuzz=FuzzVerify` and `-fuzz=FuzzVerifySecret` in `internal/identity`) cover the request parser, the token verifier and the stored-hash decoder; CI runs each for a short burst. A regression test builds a consistently rewritten ledger — which `VerifyChain` accepts — and checks that the signed anchors reject it.

`go test ./... ./sdk/... -v` runs the full suite (parser, proxy, identity, finops, compliance, config, MCP, SDK client). It covers, among other things: rejecting a compliance chain with tampered content or a record deleted from the middle, anti-privilege-escalation for scopes, a loop of repeated requests blocked exactly at the budget limit, a suspended agent rejected both at validation and when requesting a new token, recognition of MCP methods and the priority of per-tool scopes over the upstream's generic one, and the SDK client (token caching, automatic refresh, `Authorization` injection through `Do` and through `HTTPClient()`).

## Next steps

Natural directions to continue: managing the identity key through a dedicated authority (SPIRE) or an HSM/KMS, publishing ledger anchors to an external append-only store (transparency log / object-lock bucket), proof-of-possession tokens (DPoP/mTLS), a shared FinOps/compliance store for multiple Nexus instances running in parallel, and a changelog for the `sdk/` module (it is already installable with `go get github.com/chirataandrei/Nexus/sdk`).

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
