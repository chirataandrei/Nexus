# Nexus SDK (Go)

A Go client for [Nexus Trust Protocol](../README.md). It removes the need for an agent to manage its own long-lived secrets or token-refresh logic — the client does identity "bootstrap" once, caches the token, and refreshes it automatically before it expires.

An independent Go module, with no dependency on the Nexus server's code — just `net/http` and the standard library.

## Installation

```bash
go get github.com/nexus-trust-protocol/sdk-go
```

(In this repo, the module lives at `gateway/sdk` — to use it locally without publishing it, add a `replace` directive to your project's `go.mod`: `replace github.com/nexus-trust-protocol/sdk-go => /path/to/gateway/sdk`.)

## 60-second usage

```go
package main

import (
	"net/http"

	nexussdk "github.com/nexus-trust-protocol/sdk-go"
)

func main() {
	client := nexussdk.New(
		"https://nexus.your-company.com", // the gateway's address
		"agent-demo-1",                   // agent_id registered with Nexus
		"the-bootstrap-secret",           // distributed separately, once
		"current-task-1",                 // identifier for the current task
		nexussdk.WithScopes("llm:openai:invoke"),
	)

	req, _ := http.NewRequest(http.MethodPost, "https://nexus.your-company.com/v1/openai/chat/completions", nil)
	resp, err := client.Do(req) // automatically attaches a valid JWT-SVID
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	// ... read resp ...
}
```

Run the full example from `examples/basic`:

```bash
cd sdk
go run ./examples/basic -base-url http://localhost:8080 -agent-id agent-demo-1 -secret "your-secret"
```

## Plugging into an existing SDK (e.g. the OpenAI client)

`Client.HTTPClient()` returns a full `*http.Client` that injects and refreshes the token automatically on every request sent through it — you can hand it directly to any SDK that accepts a custom `*http.Client`:

```go
nexusClient := nexussdk.New(baseURL, agentID, secret, taskID)

openaiClient := openai.NewClient(
    option.WithBaseURL(baseURL + "/v1/openai"),
    option.WithHTTPClient(nexusClient.HTTPClient()),
)
// every openaiClient.* call goes through Nexus, with identity attached automatically.
```

## API

| Function/method | What it does |
|---|---|
| `nexussdk.New(baseURL, agentID, secret, taskID, opts...)` | Builds the client. |
| `WithScopes(scopes...)` | Explicitly requests a subset of scopes (must be a subset of the agent's `allowed_scopes` in Nexus). |
| `WithTTL(d)` | Requests a specific token TTL (still capped by the server's policy). |
| `WithHTTPClient(c)` | Uses a custom base `*http.Client` (timeouts, proxy, etc.). |
| `client.Token(ctx)` | Returns a valid JWT-SVID, from cache or freshly refreshed. |
| `client.Do(req)` | Executes an HTTP request through Nexus with the token attached. |
| `client.HTTPClient()` | Returns a drop-in `*http.Client` with automatic token attachment. |

## Guarantees and limitations

- The token is automatically refreshed 30 seconds before it expires — no request should fail because of an expiration happening mid-request.
- The client is safe for concurrent use (a single `Client` can be used from multiple goroutines at once).
- A `Client` corresponds to a single `(agent_id, task_id)`. For different tasks of the same agent, build separate `Client` instances (Nexus JWT-SVIDs are strictly tied to a single task).
- The bootstrap secret remains the caller's responsibility — the SDK doesn't persist it, doesn't log it, and only ever sends it to the configured gateway's token endpoint.
