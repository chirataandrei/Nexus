// The nexus-agentctl command is a development utility for generating
// new entries in configs/agents.json: it computes secret_hash without
// this program ever writing the plaintext secret to disk.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"nexus-gateway/internal/admin"
	"nexus-gateway/internal/identity"
	"nexus-gateway/internal/keystore"
)

func main() {
	agentID := flag.String("agent-id", "", "the agent's ID (required)")
	secret := flag.String("secret", "", "the bootstrap secret, in plaintext — used only to compute the hash (required)")
	scopes := flag.String("scopes", "", "comma-separated list of allowed scopes, e.g.: llm:openai:invoke,tools:internal:invoke")
	maxTTL := flag.Int("max-ttl-seconds", 0, "optional max TTL for this agent's tokens (0 = use the registry's default_max_ttl_seconds)")
	genAdmin := flag.Bool("gen-admin-token", false, "generate an admin token and print it with its admin_token_sha256 for config.json")
	genSecret := flag.Bool("gen-secret", false, "generate a random bootstrap secret for the agent (printed once to stderr)")
	showPub := flag.String("show-pubkey", "", "print kid and public key of a key file, for the retired-keys file when rotating")
	flag.Parse()

	if *genAdmin {
		tok, err := admin.GenerateToken()
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		fmt.Printf("admin token (keep secret, shown once): %s\n\"admin_token_sha256\": \"%s\"\n", tok, admin.HashToken(tok))
		return
	}
	if *showPub != "" {
		priv, _, err := keystore.LoadOrCreate(*showPub)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		pub := priv.Public().(ed25519.PublicKey)
		fmt.Printf("{\"%s\": \"%s\"}\n", keystore.KeyID(pub), keystore.EncodePublic(pub))
		return
	}
	if *genSecret && *secret == "" {
		b := make([]byte, 24)
		_, _ = rand.Read(b)
		*secret = hex.EncodeToString(b)
		fmt.Fprintf(os.Stderr, "generated secret (shown once, give it to the agent): %s\n", *secret)
	}

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
