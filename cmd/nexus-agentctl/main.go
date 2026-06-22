// Comanda nexus-agentctl este un utilitar de dezvoltare pentru a genera
// înregistrări noi în configs/agents.json: calculează secret_hash fără ca
// secretul în clar să fie scris vreodată pe disc de către acest program.
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
	agentID := flag.String("agent-id", "", "ID-ul agentului (obligatoriu)")
	secret := flag.String("secret", "", "Secretul de bootstrap, în clar — folosit doar pentru a calcula hash-ul (obligatoriu)")
	scopes := flag.String("scopes", "", "Listă de scope-uri permise, separate prin virgulă, ex: llm:openai:invoke,tools:internal:invoke")
	maxTTL := flag.Int("max-ttl-seconds", 0, "TTL maxim opțional pentru tokenurile acestui agent (0 = folosește default_max_ttl_seconds din registru)")
	flag.Parse()

	if *agentID == "" || *secret == "" {
		fmt.Fprintln(os.Stderr, "eroare: --agent-id și --secret sunt obligatorii")
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
		fmt.Fprintln(os.Stderr, "eroare la serializare:", err)
		os.Exit(1)
	}

	fmt.Println("// Adaugă această înregistrare în lista \"agents\" din configs/agents.json:")
	fmt.Println(string(out))
	fmt.Fprintln(os.Stderr, "\nNotă: secretul în clar NU este salvat nicăieri de acest program — reține-l separat și distribuie-l agentului printr-un canal sigur.")
}
