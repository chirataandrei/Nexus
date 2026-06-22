# Nexus Trust Protocol — Gateway

Reverse proxy Layer 7 scris în Go (doar bibliotecă standard, fără dependențe externe) care intermediază traficul dintre agenții IA și modelele LLM / serviciile interne. Elimină cheile API statice (fiecare agent obține o identitate criptografică efemeră, inspirată de WIMSE/SPIFFE), aplică buget în timp real per agent, scrie fiecare cerere într-un registru tamper-evident, și recunoaște nativ Model Context Protocol (MCP).

## Structura proiectului

```
gateway/
  go.work               workspace Go: leagă modulul gateway de modulul sdk
  cmd/nexus-gateway/    punctul de intrare (main.go)
  cmd/nexus-agentctl/   utilitar dev: generează secret_hash pentru agents.json
  internal/config/      încărcare și validare configurație (JSON)
  internal/parser/      detecție REST/JSON-RPC/MCP, extragere metadate
  internal/mcp/         recunoaștere metode MCP, extragere nume tool
  internal/proxy/       rutare pe prefix de path + hook-uri de extensie
  internal/logging/     jurnalizare structurată (stdout, JSON) + Fanout
  internal/identity/    AIMS — JWT-SVID, registru de agenți, validator
  internal/finops/      ledger de cost, politici de buget, dashboard
  internal/compliance/  lanț WORM tamper-evident, kill-switch
  sdk/                  SDK client Go, modul Go separat (sdk/go.mod)
    examples/basic/      exemplu de utilizare a SDK-ului
  docs/MCP.md           cum funcționează compatibilitatea MCP + scope-uri per-tool
  data/                              lanțul de conformitate (generat la rulare, ignorat de git)
  configs/config.json                exemplu de configurare gateway
  configs/agents.json                 exemplu de registru de agenți
  configs/finops_policies.json        exemplu de politici de buget
```

## Rutare și protocoale

`internal/parser` interceptează cereri HTTP/REST și JSON-RPC pe baza unui prefix de path configurat per upstream, iar `internal/proxy` le rutează către upstream-ul corect (model LLM extern sau serviciu intern), cu suport de "strip prefix". Fiecare cerere e logată structurat (JSON pe stdout): metodă HTTP, path, protocol detectat, metoda JSON-RPC, durată, status code. Anteturile sensibile (`Authorization`, `X-Api-Key`, `Cookie`) sunt mascate automat.

Pe lângă JSON-RPC generic, gateway-ul recunoaște explicit vocabularul Model Context Protocol (`tools/call`, `tools/list`, `resources/*`, `prompts/*`, `notifications/*`) — `RequestMeta.Protocol` devine `"MCP"` în loc de generic `"JSON-RPC"`, iar pentru `tools/call` numele exact al instrumentului apelat este extras în `RequestMeta.MCPTool`. Detalii: [`docs/MCP.md`](docs/MCP.md).

## Identitate (AIMS — Agent Identity Management System)

Niciun secret pe termen lung nu circulă către upstream-uri. Un agent face "bootstrap" o singură dată: trimite `agent_id` + un secret pre-distribuit la `POST /nexus/identity/token` și primește înapoi un **JWT-SVID** — un token semnat Ed25519, legat strict de un `agent_id` + `task_id` + un set explicit de `scopes`, valabil implicit 5 minute. Fiecare token are un `sub` de forma `spiffe://<trust_domain>/agent/<agent_id>/task/<task_id>`.

`internal/identity.SPIFFEValidator` respinge automat orice cerere fără antet `Authorization: Bearer <token>`, cu semnătură invalidă, expirată, dintr-un alt domeniu de încredere, sau fără scope-ul cerut explicit de rută. Registrul de agenți (`configs/agents.json`) definește `allowed_scopes` per agent — orice scope cerut care nu este în `allowed_scopes` este respins cu `403` (anti-escaladare de privilegii). `parser.RequestMeta` distinge `AgentID` (antet nesigur, doar depanare) de `VerifiedAgentID`/`SPIFFEID`/`VerifiedScopes` (populate exclusiv după o verificare criptografică reușită).

Instrumente diferite din spatele aceluiași upstream MCP pot cere permisiuni diferite: `config.Upstream.ToolScopes` (hartă `nume_tool -> scope`) face ca, de exemplu, `read_email` să ceară `tools:email:read` și `delete_email` să ceară `tools:email:delete`, chiar dacă trec prin același upstream.

## Buget (ruterul FinOps)

Înainte ca o cerere să ajungă la LLM, `internal/finops.Enforcer` verifică în `Ledger`-ul în memorie dacă agentul a epuizat bugetul zilnic sau limita de tokeni a sarcinii curente — dacă da, cererea e respinsă cu `429`, fără să mai consume vreun token costisitor. `internal/finops.Recorder` citește `usage` din răspunsul LLM (OpenAI/Anthropic) prin `ModifyResponse` al reverse proxy-ului și actualizează ledger-ul, fără să modifice răspunsul trimis agentului. `max_tokens_per_task` limitează tokenii cumulați într-o singură sarcină, indiferent de câte cereri separate face agentul — un circuit breaker direct împotriva buclelor de halucinație recurentă.

Dashboard simplu la `GET /nexus/finops/dashboard`, plus API la `/nexus/finops/usage` și `/nexus/finops/policies`.

## Conformitate și kill-switch

Fiecare cerere generează o înregistrare în `internal/compliance.Chain`, care include hash-ul ei și hash-ul înregistrării precedente — un mini-blockchain local, scris doar prin adăugare, cu `fsync` la fiecare scriere. Orice modificare retroactivă (editare, ștergere, reordonare) rupe lanțul de hash-uri și e detectabilă: `OpenChain` re-verifică integral lanțul existent la pornire, iar dacă a fost modificat în afara gateway-ului, pornirea e refuzată.

`internal/compliance.Sink` loghează la fiecare cerere: identitatea verificată *și* cea declarată, instrumentul/upstream-ul apelat, decizia finală, status, durată, cheltuiala cumulată de azi, și promptul (digest SHA-256 integral + extras lizibil trunchiat configurabil). Retenția minimă de 6 luni e impusă la nivel de configurare.

Un operator poate suspenda instantaneu și global un agent: `POST /nexus/control/suspend|resume`, `GET /nexus/control/suspended` — cererile cu token deja emis și emiterea de tokenuri noi sunt ambele blocate imediat, și fiecare acțiune e ea însăși auditată în lanț. `GET /nexus/compliance/verify` confirmă în orice moment integritatea istoricului.

## SDK pentru dezvoltatori

`sdk/` e un modul Go separat, fără nicio dependență de codul serverului (`internal/`), care gestionează automat bootstrap-ul de identitate, cache-ul și reîmprospătarea tokenului JWT-SVID. Se poate conecta la orice SDK existent printr-un `*http.Client` drop-in (`client.HTTPClient()`). Vezi [`sdk/README.md`](sdk/README.md) pentru instalare și exemple complete, și `sdk/examples/basic` pentru un program rulabil.

## Limitări cunoscute

- Cheia Ed25519 a autorității de identitate e generată în memorie la pornire — un restart invalidează tokenurile emise anterior.
- `Ledger`-ul FinOps e în memoria unui singur proces — mai multe instanțe Nexus în paralel ar avea nevoie de un store partajat (ex. Redis).
- Lanțul de conformitate e un singur fișier local, pe o singură instanță; scrierea e fail-open la eroare; nu există purjare automată la expirarea retenției.
- Integrarea cu portofele non-custodial (Locus, Skyfire) menționată în propunerea inițială rămâne în afara scopului actual.
- Compatibilitatea MCP recunoaște forma mesajelor JSON-RPC, nu implementează un server/client MCP complet (handshake, capabilități, transport SSE/stdio); cereri JSON-RPC batch nu sunt despachetate individual.

## Rulare locală

Necesită Go 1.22+.

```bash
cd gateway
go build ./...
go test ./... ./sdk/...     # gateway + sdk
go run ./cmd/nexus-gateway -config configs/config.json
```

`go.work` din rădăcina `gateway/` leagă cele două module Go (gateway-ul propriu-zis și SDK-ul client) astfel încât comenzi precum `go test ./... ./sdk/...` să funcționeze dintr-un singur loc, fără ca cele două să fie cuplate la nivel de cod — SDK-ul nu importă nimic din `internal/`.

Implicit, gateway-ul ascultă pe `:8080`, domeniul de încredere este `nexus.trust`, retenția de conformitate este 6 luni, și rutează:

| Prefix path         | Upstream                     | Scope necesar              | Preț / 1000 tokeni |
|----------------------|-------------------------------|------------------------------|----------------------|
| `/v1/openai/...`     | `https://api.openai.com`      | `llm:openai:invoke`          | $0.01 |
| `/v1/anthropic/...`  | `https://api.anthropic.com`   | `llm:anthropic:invoke`       | $0.015 |
| `/v1/internal/...`   | `http://localhost:9000`       | `tools:internal:invoke` (sau scope per-tool, vezi `tool_scopes`) | $0 |

### 1. Înregistrează un agent și cere un JWT-SVID

```bash
go run ./cmd/nexus-agentctl -agent-id agent-demo-1 -secret "un-secret" -scopes "llm:openai:invoke"
# copiază rezultatul în configs/agents.json

TOKEN=$(curl -s -X POST http://localhost:8080/nexus/identity/token \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"agent-demo-1","secret":"un-secret","task_id":"task-1"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")

curl http://localhost:8080/v1/openai/models -H "Authorization: Bearer $TOKEN"
```

Sau, echivalent, din cod Go folosind SDK-ul (fără să gestionezi manual tokenul):

```go
client := nexussdk.New("http://localhost:8080", "agent-demo-1", "un-secret", "task-1")
resp, err := client.Do(req) // atașează automat Authorization: Bearer <token>
```

### 2. Kill-switch

```bash
curl -X POST http://localhost:8080/nexus/control/suspend \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"agent-demo-1","reason":"comportament anormal","operator":"andrei"}'

curl http://localhost:8080/nexus/control/suspended

curl -X POST http://localhost:8080/nexus/control/resume \
  -H "Content-Type: application/json" -d '{"agent_id":"agent-demo-1","operator":"andrei"}'
```

### 3. Verifică integritatea registrului de conformitate

```bash
curl http://localhost:8080/nexus/compliance/verify
# {"ok": true, "verified_records": N}
```

### 4. Dashboard FinOps

```
http://localhost:8080/nexus/finops/dashboard
```

## Teste

`go test ./... ./sdk/... -v` rulează suita completă (parser, proxy, identity, finops, compliance, config, MCP, SDK client). Acoperă, printre altele: respingerea unui lanț de conformitate cu conținut modificat sau cu o înregistrare ștearsă din mijloc, anti-escaladare de scope, o buclă de cereri repetate blocată exact la limita bugetului, un agent suspendat respins atât la validare cât și la cererea unui token nou, recunoașterea metodelor MCP și prioritatea scope-ului per-tool față de cel generic al upstream-ului, și clientul SDK (cache token, refresh automat, injectare `Authorization` prin `Do` și prin `HTTPClient()`).

## Următorii pași

Direcții naturale de continuare: persistarea cheii de identitate printr-o autoritate dedicată (SPIRE), un store FinOps/conformitate partajat pentru mai multe instanțe Nexus în paralel, și publicarea modulului `sdk/` ca pachet open-source independent (CI, versionare semantică, changelog).
