# Nexus Trust Protocol — Gateway

A Layer 7 reverse proxy written in Go (standard library only, no external dependencies) that sits between AI agents and LLM models / internal services. It eliminates static API keys (each agent gets an ephemeral cryptographic identity, inspired by WIMSE/SPIFFE), enforces real-time per-agent budgets, writes every request to a tamper-evident ledger, and natively recognizes the Model Context Protocol (MCP).

## Project structure

```
gateway/
  go.work               Go workspace: links the gateway module to the sdk module
  cmd/nexus-gateway/    entry point (main.go)
  cmd/nexus-agentctl/   dev utility: generates secret_hash for agents.json
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

Different tools behind the same MCP upstream can require different permissions: `config.Upstream.ToolScopes` (a `tool_name -> scope` map) lets, for example, `read_email` require `tools:email:read` and `delete_email` require `tools:email:delete`, even though both go through the same upstream.

## Budget (the FinOps router)

Before a request reaches the LLM, `internal/finops.Enforcer` checks the in-memory `Ledger` to see whether the agent has already exhausted its daily budget or the current task's token limit — if so, the request is rejected with `429`, without consuming a single costly token. `internal/finops.Recorder` reads `usage` from the LLM's response (OpenAI/Anthropic) through the reverse proxy's `ModifyResponse`, and updates the ledger without altering the response sent to the agent. `max_tokens_per_task` caps the tokens accumulated within a single task, no matter how many separate requests the agent makes — a direct circuit breaker against recurring hallucination loops.

A simple dashboard is available at `GET /nexus/finops/dashboard`, plus an API at `/nexus/finops/usage` and `/nexus/finops/policies`.

## Compliance and kill switch

Every request generates a record in `internal/compliance.Chain`, which includes its own hash and the hash of the previous record — a local mini-blockchain, written strictly by appending, with `fsync` on every write. Any retroactive change (editing, deleting, reordering) breaks the hash chain and is detectable: `OpenChain` fully re-verifies the existing chain at startup, and if it was modified outside the gateway, startup is refused.

`internal/compliance.Sink` logs, for every request: the verified identity *and* the claimed one, the tool/upstream called, the final decision, status, duration, today's cumulative spend, and the prompt (full SHA-256 digest + a configurable, truncated readable excerpt). The minimum 6-month retention is enforced at the configuration level.

An operator can instantly and globally suspend an agent: `POST /nexus/control/suspend|resume`, `GET /nexus/control/suspended` — requests using an already-issued token and the issuance of new tokens are both blocked immediately, and each action is itself recorded in the chain. `GET /nexus/compliance/verify` confirms the history's integrity at any time.

## SDK for developers

`sdk/` is a separate Go module, with no dependency on the server's code (`internal/`), that automatically handles identity bootstrap, caching, and refreshing of the JWT-SVID token. It can plug into any existing SDK through a drop-in `*http.Client` (`client.HTTPClient()`). See [`sdk/README.md`](sdk/README.md) for installation and full examples, and `sdk/examples/basic` for a runnable program.

## Known limitations

- The identity authority's Ed25519 key is generated in memory at startup — a restart invalidates previously issued tokens.
- The FinOps `Ledger` lives in a single process's memory — multiple Nexus instances running in parallel would need a shared store (e.g. Redis).
- The compliance chain is a single local file on a single instance; writes are fail-open on error; there's no automatic purging once retention expires.
- The non-custodial wallet integration (Locus, Skyfire) mentioned in the original proposal remains out of scope for now.
- MCP compatibility recognizes the shape of JSON-RPC messages; it doesn't implement a full MCP server/client (handshake, capability negotiation, SSE/stdio transport); JSON-RPC batch requests aren't unpacked individually.

## Running locally

Requires Go 1.22+.

```bash
cd gateway
go build ./...
go test ./... ./sdk/...     # gateway + sdk
go run ./cmd/nexus-gateway -config configs/config.json
```

`go.work` at the root of `gateway/` links the two Go modules (the gateway itself and the client SDK) so commands like `go test ./... ./sdk/...` work from a single place, without the two being coupled at the code level — the SDK doesn't import anything from `internal/`.

By default, the gateway listens on `:8080`, the trust domain is `nexus.trust`, the compliance retention is 6 months, and it routes:

| Path prefix         | Upstream                     | Required scope             | Price / 1000 tokens |
|----------------------|-------------------------------|------------------------------|----------------------|
| `/v1/openai/...`     | `https://api.openai.com`      | `llm:openai:invoke`          | $0.01 |
| `/v1/anthropic/...`  | `https://api.anthropic.com`   | `llm:anthropic:invoke`       | $0.015 |
| `/v1/internal/...`   | `http://localhost:9000`       | `tools:internal:invoke` (or a per-tool scope, see `tool_scopes`) | $0 |

### 1. Register an agent and request a JWT-SVID

```bash
go run ./cmd/nexus-agentctl -agent-id agent-demo-1 -secret "a-secret" -scopes "llm:openai:invoke"
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

### 2. Kill switch

```bash
curl -X POST http://localhost:8080/nexus/control/suspend \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"agent-demo-1","reason":"abnormal behavior","operator":"andrei"}'

curl http://localhost:8080/nexus/control/suspended

curl -X POST http://localhost:8080/nexus/control/resume \
  -H "Content-Type: application/json" -d '{"agent_id":"agent-demo-1","operator":"andrei"}'
```

### 3. Verify the compliance ledger's integrity

```bash
curl http://localhost:8080/nexus/compliance/verify
# {"ok": true, "verified_records": N}
```

### 4. FinOps dashboard

```
http://localhost:8080/nexus/finops/dashboard
```

## Tests

`go test ./... ./sdk/... -v` runs the full suite (parser, proxy, identity, finops, compliance, config, MCP, SDK client). It covers, among other things: rejecting a compliance chain with tampered content or a record deleted from the middle, anti-privilege-escalation for scopes, a loop of repeated requests blocked exactly at the budget limit, a suspended agent rejected both at validation and when requesting a new token, recognition of MCP methods and the priority of per-tool scopes over the upstream's generic one, and the SDK client (token caching, automatic refresh, `Authorization` injection through `Do` and through `HTTPClient()`).

## Next steps

Natural directions to continue: persisting the identity key through a dedicated authority (SPIRE), a shared FinOps/compliance store for multiple Nexus instances running in parallel, and actually publishing the `sdk/` module as an independent open-source package (CI, semantic versioning, changelog).
