# Native Model Context Protocol (MCP) compatibility

Nexus Trust Protocol natively recognizes [MCP](https://modelcontextprotocol.io) (Model Context Protocol) messages, on top of generic JSON-RPC detection. The goal: the gateway doesn't just route JSON-RPC traffic, it understands exactly which **tool** an agent is calling — information that identity, FinOps, and the compliance ledger can then use with fine granularity.

## What it actually does

The `internal/mcp` package recognizes the standard MCP methods (`initialize`, `tools/list`, `tools/call`, `resources/list`, `resources/read`, `prompts/list`, `prompts/get`, `ping`, plus any `notifications/*`). `internal/parser` uses this recognition: for any JSON-RPC message whose method is an MCP one, `RequestMeta.Protocol` becomes `"MCP"` (instead of the generic `"JSON-RPC"`), and for `tools/call`, `RequestMeta.MCPTool` is populated with the tool's exact name (`params.name`).

This `MCPTool` is available throughout the rest of the flow: logging (`mcp_tool` in the JSON logs on stdout), the compliance ledger (`tool` in the WORM chain — the tool's exact name, not just the generic "tools/call"), and, most importantly, in **routing/authorization**.

## Per-tool scopes

A `required_scope` can be defined at the level of the whole upstream — every call to `/v1/internal/...` would require, say, `tools:internal:invoke`, regardless of which specific tool is called through MCP behind it. For finer control, `config.Upstream` has an optional `tool_scopes` field, a `tool_name -> scope` map:

```json
{
  "name": "internal-tools",
  "path_prefix": "/v1/internal",
  "target_url": "http://localhost:9000",
  "required_scope": "tools:internal:invoke",
  "tool_scopes": {
    "read_email": "tools:email:read",
    "send_email": "tools:email:send",
    "delete_email": "tools:email:delete"
  }
}
```

If an MCP `tools/call` request calls a tool present in `tool_scopes`, that tool's specific scope **overrides** the generic `required_scope` for that exact request — the rest of the route (routing, FinOps, compliance) is unchanged. A called tool that is NOT in the map keeps using the upstream's generic `required_scope` (a safe fallback — nothing implicitly becomes "more permissive").

This is the exact example from Nexus Trust Protocol's original proposal: *"the agent has permission to read the email account, but not to delete"* — now implemented as a configuration policy, not hardcoded logic.

### Why it matters

An agent with a JWT-SVID containing only the `tools:email:read` scope can call `read_email` through MCP, but gets `401` from `SPIFFEValidator` if it tries `delete_email` — even though both tools go through the same MCP upstream. The granularity of access control follows the real granularity of the tools an agent can use, not just the granularity of HTTP routes.

## Example of a request recognized as MCP

```bash
curl -X POST http://localhost:8080/v1/internal/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"read_email","arguments":{}}}'
```

The gateway's log will show `protocol=MCP`, `jsonrpc_method=tools/call`, `mcp_tool=read_email`, `required_scope=tools:email:read` (taken from `tool_scopes`, not from the generic `required_scope`).

## Known limitations

- A full MCP server/client isn't implemented (the `initialize` handshake, negotiated capabilities, stdio transport) — Nexus is an HTTP proxy that **recognizes the shape of messages**, not an MCP endpoint itself. For the common case (agent → Nexus → a real MCP server over HTTP), this level of recognition is enough for routing/authorization/audit.
- Verified against a real implementation: `integration/mcp` runs the official MCP Go SDK client and server through the real gateway binary over Streamable HTTP (initialize, notifications, `tools/list`, `tools/call`, SSE streams), checks that a tool outside the agent's scopes never reaches the server, and that the ledger records the exact tool names. Run it with `make test-mcp`. It found a real bug: streamed (SSE) responses were buffered until the upstream closed, which stalled MCP sessions; they are now passed through as they arrive and their usage is metered when the stream ends.
- Spend metering of an SSE stream reads the last `data:` event that carries `usage`; a stream without one is not metered (the per-request reservation still applies while it is in flight).
- JSON-RPC batch requests (an array of messages in a single body) are rejected with `400`: per-tool scopes are decided from a single parsed message, so a batch could otherwise run calls under the upstream's broader scope.
