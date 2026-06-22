# Nexus SDK (Go)

Client Go pentru [Nexus Trust Protocol](../README.md). Elimină nevoia ca un agent să gestioneze el însuși secrete pe termen lung sau logica de refresh a tokenurilor — clientul face "bootstrap-ul" de identitate o singură dată, ține tokenul în cache și îl reîmprospătează automat înainte să expire.

Modul Go independent, fără nicio dependență de codul serverului Nexus — doar `net/http` și biblioteca standard.

## Instalare

```bash
go get github.com/nexus-trust-protocol/sdk-go
```

(În acest repo, modulul e la `gateway/sdk` — pentru a-l folosi local fără publicare, `replace`-uiește-l în `go.mod`-ul proiectului tău: `replace github.com/nexus-trust-protocol/sdk-go => /cale/catre/gateway/sdk`.)

## Utilizare în 60 de secunde

```go
package main

import (
	"net/http"

	nexussdk "github.com/nexus-trust-protocol/sdk-go"
)

func main() {
	client := nexussdk.New(
		"https://nexus.compania-ta.com", // adresa gateway-ului
		"agent-demo-1",                  // agent_id înregistrat în Nexus
		"secretul-de-bootstrap",         // distribuit separat, o singură dată
		"task-curent-1",                 // identificatorul sarcinii curente
		nexussdk.WithScopes("llm:openai:invoke"),
	)

	req, _ := http.NewRequest(http.MethodPost, "https://nexus.compania-ta.com/v1/openai/chat/completions", nil)
	resp, err := client.Do(req) // atașează automat un JWT-SVID valid
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	// ... citește resp ...
}
```

Rulează exemplul complet din `examples/basic`:

```bash
cd sdk
go run ./examples/basic -base-url http://localhost:8080 -agent-id agent-demo-1 -secret "secretul-tau"
```

## Conectarea la un SDK existent (ex. clientul OpenAI)

`Client.HTTPClient()` returnează un `*http.Client` complet, care injectează și reîmprospătează automat tokenul pe orice cerere trimisă prin el — îl poți da direct oricărui SDK care acceptă un `*http.Client` personalizat:

```go
nexusClient := nexussdk.New(baseURL, agentID, secret, taskID)

openaiClient := openai.NewClient(
    option.WithBaseURL(baseURL + "/v1/openai"),
    option.WithHTTPClient(nexusClient.HTTPClient()),
)
// orice apel openaiClient.* trece prin Nexus, cu identitate atașată automat.
```

## API

| Funcție/metodă | Ce face |
|---|---|
| `nexussdk.New(baseURL, agentID, secret, taskID, opts...)` | Construiește clientul. |
| `WithScopes(scopes...)` | Cere explicit un subset de scope-uri (trebuie să fie un subset din `allowed_scopes` al agentului în Nexus). |
| `WithTTL(d)` | Cere un TTL specific pentru token (limitat de politica serverului). |
| `WithHTTPClient(c)` | Folosește un `*http.Client` de bază personalizat (timeouts, proxy etc.). |
| `client.Token(ctx)` | Returnează un JWT-SVID valid, din cache sau reîmprospătat. |
| `client.Do(req)` | Execută o cerere HTTP prin Nexus cu tokenul atașat. |
| `client.HTTPClient()` | Returnează un `*http.Client` drop-in cu atașare automată de token. |

## Garanții și limitări

- Tokenul este reîmprospătat automat cu 30 de secunde înainte de expirare — nicio cerere nu ar trebui să rateze din cauza unei expirări chiar în timpul ei.
- Clientul este sigur pentru utilizare concurentă (un singur `Client` poate fi folosit din mai multe goroutine simultan).
- Un `Client` corespunde unui singur `(agent_id, task_id)`. Pentru sarcini diferite ale aceluiași agent, construiește instanțe `Client` separate (JWT-SVID-urile Nexus sunt legate strict de o singură sarcină).
- Secretul de bootstrap rămâne responsabilitatea apelantului — SDK-ul nu îl persistă, nu îl loghează și nu îl trimite decât către endpoint-ul de token al gateway-ului configurat.
