# Compatibilitate nativă cu Model Context Protocol (MCP)

Nexus Trust Protocol recunoaște nativ mesajele [MCP](https://modelcontextprotocol.io) (Model Context Protocol), peste detecția JSON-RPC generică. Scopul: gateway-ul nu doar rutează trafic JSON-RPC, ci înțelege exact ce **instrument (tool)** apelă un agent — informație pe care identitatea, FinOps și registrul de conformitate o pot folosi cu granularitate fină.

## Ce face concret

Pachetul `internal/mcp` recunoaște metodele standard MCP (`initialize`, `tools/list`, `tools/call`, `resources/list`, `resources/read`, `prompts/list`, `prompts/get`, `ping`, plus orice `notifications/*`). `internal/parser` folosește această recunoaștere: pentru orice mesaj JSON-RPC a cărui metodă este una MCP, `RequestMeta.Protocol` devine `"MCP"` (în loc de generic `"JSON-RPC"`), iar pentru `tools/call`, `RequestMeta.MCPTool` este populat cu numele exact al instrumentului (`params.name`).

Acest `MCPTool` este disponibil în tot restul fluxului: logging (`mcp_tool` în log-urile JSON de pe stdout), registrul de conformitate (`tool` în lanțul WORM — numele exact al instrumentului, nu doar "tools/call" generic) și, cel mai important, în **rutare/autorizare**.

## Scope-uri per-tool

Un `required_scope` poate fi definit la nivelul întregului upstream — toate apelurile către `/v1/internal/...` ar cere, de exemplu, `tools:internal:invoke`, indiferent ce instrument anume e apelat prin MCP în spate. Pentru control mai fin, `config.Upstream` are un câmp opțional `tool_scopes`, o hartă `nume_tool -> scope`:

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

Dacă o cerere MCP `tools/call` apelează un instrument prezent în `tool_scopes`, scope-ul lui specific **suprascrie** `required_scope` generic pentru exact acea cerere — restul rutei (rutare, FinOps, conformitate) este neschimbat. Un instrument apelat care NU este în hartă continuă să folosească `required_scope` generic al upstream-ului (fallback sigur — nimic nu devine implicit "mai permisiv").

Acesta este exemplul exact din propunerea inițială a Nexus Trust Protocol: *"agentul are permisiunea de a citi contul de e-mail, dar nu de a șterge"* — implementat acum ca politică de configurare, nu ca logică hardcodată.

### De ce este important

Un agent cu un JWT-SVID care conține doar scope-ul `tools:email:read` poate apela `read_email` prin MCP, dar primește `401` de la `SPIFFEValidator` dacă încearcă `delete_email` — chiar dacă ambele instrumente trec prin același upstream MCP. Granularitatea controlului de acces urmează granularitatea reală a instrumentelor pe care agentul le poate folosi, nu doar granularitatea rutelor HTTP.

## Exemplu de cerere recunoscută ca MCP

```bash
curl -X POST http://localhost:8080/v1/internal/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"read_email","arguments":{}}}'
```

Logul gateway-ului va arăta `protocol=MCP`, `jsonrpc_method=tools/call`, `mcp_tool=read_email`, `required_scope=tools:email:read` (preluat din `tool_scopes`, nu din `required_scope` generic).

## Limitări cunoscute

- Nu este implementat un server/client MCP complet (handshake `initialize`, capabilități negociate, transport SSE/stdio) — Nexus este un proxy HTTP care **recunoaște forma mesajelor**, nu un endpoint MCP propriu-zis. Pentru cazul comun (agent → Nexus → server MCP real prin HTTP), acest nivel de recunoaștere este suficient pentru rutare/autorizare/audit.
- Cereri JSON-RPC batch (array de mesaje într-un singur body) nu sunt despachetate individual — fiecare cerere HTTP este tratată ca un singur mesaj.
