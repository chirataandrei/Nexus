// Exemplu minimal de utilizare a SDK-ului Nexus: un "agent" care apelează
// un model LLM prin gateway, fără să gestioneze el însuși vreun secret pe
// termen lung sau vreo logică de refresh de token.
//
// Rulare (cu gateway-ul Nexus pornit local, conform README-ului principal):
//
//	go run ./examples/basic \
//	  -base-url http://localhost:8080 \
//	  -agent-id agent-demo-1 \
//	  -secret "secretul-tau" \
//	  -task-id task-exemplu-1
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
	baseURL := flag.String("base-url", "http://localhost:8080", "adresa gateway-ului Nexus")
	agentID := flag.String("agent-id", "agent-demo-1", "agent_id înregistrat în Nexus")
	secret := flag.String("secret", "", "secretul de bootstrap al agentului")
	taskID := flag.String("task-id", "task-exemplu-1", "identificatorul sarcinii curente")
	path := flag.String("path", "/v1/openai/models", "path-ul (prin Nexus) către care se face cererea")
	flag.Parse()

	if *secret == "" {
		log.Fatal("specifică -secret (secretul de bootstrap al agentului)")
	}

	// Un singur client per (agent, sarcină). Gestionează automat
	// bootstrap-ul de identitate și reîmprospătarea tokenului.
	client := nexussdk.New(*baseURL, *agentID, *secret, *taskID,
		nexussdk.WithScopes("llm:openai:invoke"),
	)

	req, err := http.NewRequest(http.MethodGet, *baseURL+*path, nil)
	if err != nil {
		log.Fatalf("nu pot construi cererea: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("cererea prin Nexus a eșuat: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("status: %d\nbody: %s\n", resp.StatusCode, body)
}
