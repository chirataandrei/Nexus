# Threat model

What Nexus protects, from whom, how, and what it deliberately does not
cover. Each mitigation names the code and the test that exercises it.

## Assets

| Asset | Why it matters |
|---|---|
| Identity signing key (`identity_key_file`) | Whoever holds it can mint a token for any agent and scope. |
| Agent bootstrap secrets (`agents.json` holds only hashes) | Exchanged for tokens; a leaked secret lets an attacker impersonate that agent. |
| JWT-SVIDs | Bearer credentials for upstreams, valid minutes. |
| Admin token | Suspend/resume agents, revoke tokens, change budgets. |
| Budget (money) | Runaway or abusive spend through the gateway. |
| Compliance ledger + anchors | The audit trail regulators and incident responders rely on. |
| Upstream credentials | Held by the gateway's environment/upstreams, never given to agents. |

## Trust boundaries and assumptions

- **Agents are untrusted.** They may be compromised, prompt-injected or malicious. They hold a bootstrap secret and short-lived tokens only.
- **The network between agent and gateway is TLS-protected by something else.** The gateway speaks plain HTTP; terminate TLS in front of it. Without TLS, tokens and secrets are visible on the wire.
- **The gateway host is trusted at runtime.** An attacker with code execution on it owns the keys (see residual risks).
- **Operators are authenticated** by the admin token, not by individual identity (no per-operator accountability beyond the `operator` string they supply).

## Threats and mitigations

### Stolen or replayed token
- Token = bearer credential; **no proof of possession**. A thief can use it from anywhere until it expires or is revoked.
- **Bounded by:** TTL (5 min default, hard ceiling 24 h, per-agent override), single `task_id` and least-privilege `scopes` per token, unique `jti`.
- **Stop it now:** `POST /nexus/control/revoke {jti}` (kills that token), `POST /nexus/control/suspend` (kills the agent, including new tokens). The `jti` appears on every ledger record, so the stolen token's activity can be found and revoked. Tests: `TestRevokedTokenIsRejectedImmediately`, `TestValidatorPopulatesJTI`.
- **Not mitigated:** reuse inside the TTL when nobody notices; revocations are in memory and reset on restart (the token then lives until `exp` at most).

### Brute force / enumeration on `POST /nexus/identity/token`
- Failures are limited per client IP and per agent+IP, `429` + `Retry-After`, checked before any hashing. Unknown agents count, so scanning agent IDs is throttled. Keying on agent+IP (not agent alone) means an attacker can't lock a legitimate agent out from another address. Tests: `TestTokenHandler_BruteForceIsRateLimited…`, `…PerIPLimitCoversAgentEnumeration`, `…SuccessResetsAgentCounter`.
- Secrets: salted PBKDF2-HMAC-SHA256, 600k iterations; constant-time compare; an unknown agent burns the same PBKDF2 work as a wrong secret (no timing/enumeration oracle). Iteration count in stored hashes is capped so an edited hash can't be a CPU bomb. Fuzzed: `FuzzVerifySecret`.
- **Residual:** limits are per process and per remote address; behind a proxy all clients share its IP unless it's the direct peer (`X-Forwarded-For` is deliberately not trusted). A distributed attacker with many IPs is limited per IP only; use high-entropy generated secrets (`nexus-agentctl -gen-secret`) — the stretching protects a *stolen* `agents.json`, not a weak secret.
- PBKDF2 cost is also a CPU-amplification vector; the limiter runs first to contain it.

### Privilege escalation
- A token request may only ask for a subset of the agent's `allowed_scopes`; per-tool scopes (`tool_scopes`) are enforced per MCP call. **JSON-RPC batches are rejected (`400`)** because the scope is decided from one parsed message — a batch would otherwise run `delete_email` under the upstream's broader scope. Tests: `TestServer_RejectsJSONRPCBatch`, `FuzzParse` (a batch never carries a tool name).
- **Residual:** only the `tools/call` name is inspected; arguments are not.

### Key compromise, restart and rotation
- The identity key persists in a 0600 file (created `O_EXCL`), tokens carry a `kid`, so restarts don't invalidate tokens and a key can be rotated: new key becomes current, the old *public* key goes in `identity_retired_keys_file` until old tokens expire. Unknown `kid` → rejected; the `kid` only selects a candidate key, the signature must still verify. Tests: `TestKeyRotation_…`.
- **Residual:** the key is a file on the gateway host (not an HSM/KMS). Compromise of the host = ability to mint tokens; rotate and revoke, review the ledger.

### Operator endpoints
- `/nexus/control/*` and `/nexus/finops/policies` require the admin token (constant-time compare of SHA-256). Denials are logged. Every suspend/resume/revoke is itself written to the ledger.
- **Residual:** single shared admin token, no per-operator identity, no rate limit on it (long random token). `/nexus/finops/usage`, the dashboard and `/nexus/compliance/verify` are unauthenticated read-only — bind them to an internal network.

### Ledger tampering
| Attacker | Outcome |
|---|---|
| Edits/deletes/reorders records, leaves other hashes | Caught by the hash chain at startup and on `/verify`. |
| Edits a record **and recomputes every hash after it** | Passes the bare chain. **Caught by signed anchors** (hash at an anchored sequence changes). Test: `TestAnchors_CompleteRewriteIsDetected`. |
| Truncates the ledger or deletes it | Caught if the cut is at or before the last anchor (`…TruncationAndDeletionDetected`). |
| Forges or removes anchors | Needs the anchor key; removing one from the middle breaks the anchor chain (`…ForgedOrRemovedAnchorsDetected`). |
| Rewrites only records **after the last anchor** | Not caught by anchors (window = anchor interval, default 100 records / 60 s; each anchor is also logged to stdout for shipping). |
| Deletes ledger **and** anchors file (or holds the anchor key) | Not caught locally. Keep the anchors on a different volume/host and/or ship the stdout `ledger_anchored` events off-box; publishing anchors to an external append-only store is the planned hardening. |
- Anchor key is separate from the identity key and rotatable the same way (`compliance_anchor_retired_keys_file`).

### Audit failure: fail-open vs fail-closed
- A compliance gateway that keeps serving when it can't log has a hole in its guarantee, but one that stops serving turns a full disk into an outage. Both are supported: `compliance_fail_closed: true` writes the request record **before** forwarding and returns `503` if it can't; default `false` logs the error and continues. Tests: `TestServer_FailClosedAuditRefusesBeforeForwarding`, `TestSink_FailClosedVetoesRequestOnWriteError`. A failed write never leaves a gap or partial line (`TestChain_FailedWriteLeavesNoGap`).
- Response and rejection records are written after the call, so even fail-closed can only log a failure there.

### Budget abuse and denial of wallet
- Daily USD budget and per-task token cap, enforced before the upstream call. With `max_cost_per_request_usd` the worst-case cost of in-flight requests is reserved atomically, so a burst can't overshoot: 500 concurrent requests → exactly `budget / cost` pass. Test: `TestBudget_ConcurrentRequestsStopExactlyAtLimit` (also run under `-race`). Without that setting a burst can overshoot (spend is recorded after the response).
- **Residual:** in-memory ledger, single instance; cost is derived from the upstream's reported `usage`.

### Malformed input
- Parser, token verifier and stored-hash decoder are fuzzed (`go test -fuzz`); the body is forwarded byte-for-byte; request bodies are size-limited (`max_body_bytes`).

## Out of scope
Prompt-injection detection or content filtering; DDoS protection beyond the limits above; multi-instance consistency (budget, revocations, kill-switch state are per process); TLS termination; non-repudiation of operator identity.
