// registry.go conține registrul agenților IA cunoscuți de Nexus —
// echivalentul unei liste de "workload-uri" autorizate să facă "bootstrap"
// (schimbul inițial al unui secret pre-distribuit pentru un JWT-SVID
// efemer). Într-o implementare SPIFFE completă, acest pas ar fi înlocuit
// de attestation la nivel de platformă (k8s, TPM etc.); aici folosim un
// secret de bootstrap simplu, stocat doar ca hash SHA-256.
package identity

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// AgentRecord descrie un agent IA înregistrat în Nexus: identitatea lui,
// hash-ul secretului de bootstrap și scope-urile maxime pe care le poate
// cere vreodată (orice cerere peste acest set este respinsă — aceasta
// este bariera anti-escaladare de privilegii).
type AgentRecord struct {
	AgentID string `json:"agent_id"`
	// SecretHash este sha256("<agent_id>:<secret>") în hex — niciodată
	// secretul în clar. Generează-l cu cmd/nexus-agentctl.
	SecretHash string `json:"secret_hash"`
	// AllowedScopes este plafonul absolut de drepturi al agentului.
	AllowedScopes []string `json:"allowed_scopes"`
	// MaxTTLSeconds, dacă setat, suprascrie TTL-ul maxim implicit al
	// registrului pentru acest agent specific (ex. un agent cu drepturi
	// mai sensibile poate primi tokenuri valabile doar 60s).
	MaxTTLSeconds int `json:"max_ttl_seconds,omitempty"`
}

// MaxTTL returnează durata maximă de viață permisă pentru un token al
// acestui agent, folosind fallback dacă agentul nu are o valoare proprie.
func (rec AgentRecord) MaxTTL(fallback time.Duration) time.Duration {
	if rec.MaxTTLSeconds > 0 {
		return time.Duration(rec.MaxTTLSeconds) * time.Second
	}
	return fallback
}

// EnsureScopesAllowed verifică că niciun scope cerut nu depășește
// AllowedScopes — un agent nu poate obține niciodată, prin cererea de
// token, mai multe drepturi decât i s-au alocat explicit de către un
// administrator.
func (rec AgentRecord) EnsureScopesAllowed(requested []string) error {
	allowed := make(map[string]bool, len(rec.AllowedScopes))
	for _, s := range rec.AllowedScopes {
		allowed[s] = true
	}
	for _, s := range requested {
		if !allowed[s] {
			return fmt.Errorf(
				"identity: scope %q nu este permis pentru agentul %q (posibilă escaladare de privilegii respinsă)",
				s, rec.AgentID,
			)
		}
	}
	return nil
}

// agentsFile este formatul JSON de pe disc pentru registrul de agenți.
type agentsFile struct {
	DefaultMaxTTLSeconds int           `json:"default_max_ttl_seconds,omitempty"`
	Agents               []AgentRecord `json:"agents"`
}

// Registry ține în memorie agenții înregistrați și TTL-ul implicit maxim.
type Registry struct {
	agents        map[string]AgentRecord
	defaultMaxTTL time.Duration
}

// LoadRegistry citește un fișier JSON de pe disc și construiește
// registrul de agenți. fallbackDefaultMaxTTL este folosit dacă fișierul
// nu specifică default_max_ttl_seconds.
func LoadRegistry(path string, fallbackDefaultMaxTTL time.Duration) (*Registry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("identity: nu pot citi registrul de agenți %s: %w", path, err)
	}

	var f agentsFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("identity: JSON invalid în %s: %w", path, err)
	}

	reg := &Registry{
		agents:        make(map[string]AgentRecord, len(f.Agents)),
		defaultMaxTTL: fallbackDefaultMaxTTL,
	}
	if f.DefaultMaxTTLSeconds > 0 {
		reg.defaultMaxTTL = time.Duration(f.DefaultMaxTTLSeconds) * time.Second
	}

	for _, a := range f.Agents {
		if a.AgentID == "" || a.SecretHash == "" {
			return nil, fmt.Errorf("identity: agent invalid (agent_id/secret_hash lipsă): %+v", a)
		}
		if _, dup := reg.agents[a.AgentID]; dup {
			return nil, fmt.Errorf("identity: agent_id duplicat în registru: %s", a.AgentID)
		}
		reg.agents[a.AgentID] = a
	}

	if len(reg.agents) == 0 {
		return nil, fmt.Errorf("identity: registrul de agenți %s este gol", path)
	}
	return reg, nil
}

// DefaultMaxTTL este TTL-ul maxim implicit al registrului (folosit pentru
// agenții care nu definesc max_ttl_seconds propriu).
func (r *Registry) DefaultMaxTTL() time.Duration {
	return r.defaultMaxTTL
}

// Authenticate verifică perechea (agentID, secret) împotriva registrului.
// Comparația se face mereu prin hash + constant-time compare, inclusiv
// pentru agenți inexistenți, ca să nu existe o diferență de timp
// observabilă între "agent inexistent" și "secret greșit".
func (r *Registry) Authenticate(agentID, secret string) (AgentRecord, error) {
	rec, found := r.agents[agentID]

	candidate := HashSecret(agentID, secret)
	stored := rec.SecretHash // gol dacă agentul nu a fost găsit

	match := subtle.ConstantTimeCompare([]byte(candidate), []byte(stored)) == 1

	if !found || !match || stored == "" {
		return AgentRecord{}, fmt.Errorf("identity: autentificare eșuată pentru agentul %q", agentID)
	}
	return rec, nil
}

// HashSecret calculează hash-ul folosit pentru stocarea secretelor de
// bootstrap. Este expus public pentru a fi folosit de cmd/nexus-agentctl
// la generarea de înregistrări noi în configs/agents.json.
func HashSecret(agentID, secret string) string {
	sum := sha256.Sum256([]byte(agentID + ":" + secret))
	return hex.EncodeToString(sum[:])
}
