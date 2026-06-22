// Minimal example of using the Nexus SDK: an "agent" that calls an LLM
// model through the gateway, without managing any long-lived secret or
// token-refresh logic itself.
//
// Run it (with the Nexus gateway running locally, per the main README):
//
//	go run ./examples/basic \
//	  -base-url http://localhost:8080 \
//	  -agent-id agent-demo-1 \
//	  -secret "your-secret" \
//	  -task-id example-task-1
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"

	nexussdk "github.com/nexus-trust-protocol/sdk-go"
)

func main() {
	baseURL := flag.String("base-url", "http://localhost:8080", "the Nexus gateway's address")
	agentID := flag.String("agent-id", "agent-demo-1", "agent_id registered with Nexus")
	secret := flag.String("secret", "", "the agent's bootstrap secret")
	taskID := flag.String("task-id", "example-task-1", "identifier for the current task")
	path := flag.String("path", "/v1/openai/models", "the path (through Nexus) the request targets")
	flag.Parse()

	if *secret == "" {
		log.Fatal("specify -secret (the agent's bootstrap secret)")
	}

	// A single client per (agent, task). Automatically handles identity
	// bootstrap and token refresh.
	client := nexussdk.New(*baseURL, *agentID, *secret, *taskID,
		nexussdk.WithScopes("llm:openai:invoke"),
	)

	req, err := http.NewRequest(http.MethodGet, *baseURL+*path, nil)
	if err != nil {
		log.Fatalf("cannot build request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("request through Nexus failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("status: %d\nbody: %s\n", resp.StatusCode, body)
}
