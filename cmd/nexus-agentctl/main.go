// The nexus-agentctl command is a development utility for generating
// new entries in configs/agents.json: it computes secret_hash without
// this program ever writing the plaintext secret to disk.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"nexus-gateway/internal/identity"
)

func main() {
	agentID := flag.String("agent-id", "", "the agent's ID (required)")
	secret := flag.String("secret", "", "the bootstrap secret, in plaintext — used only to compute the hash (required)")
	scopes := flag.String("scopes", "", "comma-separated list of allowed scopes, e.g.: llm:openai:invoke,tools:internal:invoke")
	maxTTL := flag.Int("max-ttl-seconds", 0, "optional max TTL for this agent's tokens (0 = use the registry's default_max_ttl_seconds)")
	flag.Parse()

	if *agentID == "" || *secret == "" {
		fmt.Fprintln(os.Stderr, "error: --agent-id and --secret are required")
		flag.Usage()
		os.Exit(1)
	}

	var scopeList []string
	if strings.TrimSpace(*scopes) != "" {
		for _, s := range strings.Split(*scopes, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				scopeList = append(scopeList, s)
			}
		}
	}

	rec := identity.AgentRecord{
		AgentID:       *agentID,
		SecretHash:    identity.HashSecret(*agentID, *secret),
		AllowedScopes: scopeList,
		MaxTTLSeconds: *maxTTL,
	}

	out, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "serialization error:", err)
		os.Exit(1)
	}

	fmt.Println("// Add this entry to the \"agents\" list in configs/agents.json:")
	fmt.Println(string(out))
	fmt.Fprintln(os.Stderr, "\nNote: the plaintext secret is NOT saved anywhere by this program — keep it separately and distribute it to the agent through a secure channel.")
}
