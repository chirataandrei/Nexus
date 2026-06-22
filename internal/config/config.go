// Package config încarcă configurația gateway-ului Nexus Trust Protocol:
// adresa pe care ascultă serverul și lista de upstream-uri (modele LLM,
// servicii interne) către care se rutează cererile, pe bază de prefix de
// path. Formatul este JSON simplu, fără dependențe externe, pentru a
// păstra gateway-ul compilabil doar cu biblioteca standard Go.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Upstream descrie o destinație către care Nexus poate ruta trafic:
// un model LLM extern (OpenAI, Anthropic) sau un serviciu intern al
// companiei (bază de date, API propriu).
type Upstream struct {
	// Name este identificatorul intern al upstream-ului, folosit în loguri
	// și în politicile de buget și conformitate.
	Name string `json:"name"`
	// PathPrefix este prefixul de URL pe care Nexus îl interceptează,
	// ex: "/v1/openai" sau "/v1/anthropic".
	PathPrefix string `json:"path_prefix"`
	// TargetURL este adresa reală a upstream-ului către care se face proxy.
	TargetURL string `json:"target_url"`
	// StripPrefix, dacă true, elimină PathPrefix din path înainte de a
	// trimite cererea către TargetURL (util când upstream-ul nu cunoaște
	// prefixul intern folosit de Nexus).
	StripPrefix bool `json:"strip_prefix"`
	// RequiredScope, dacă setat, obligă orice cerere către acest
	// upstream să prezinte un JWT-SVID care conține exact acest scope.
	// Gol = orice identitate validă este suficientă, fără restricție de
	// scope pe această rută.
	RequiredScope string `json:"required_scope,omitempty"`
	// PricePerThousandTokensUSD este prețul folosit de FinOps pentru a
	// calcula costul real al apelurilor către acest upstream, pe baza
	// câmpului "usage" din răspunsul modelului LLM. 0 = upstream-ul nu
	// este taxat per token (ex. un instrument intern).
	PricePerThousandTokensUSD float64 `json:"price_per_1k_tokens_usd,omitempty"`
	// ToolScopes mapează numele unui instrument MCP (ex. "send_email") la
	// scope-ul cerut pentru EXACT
	// acel instrument, mai fin decât RequiredScope (care se aplică la
	// nivelul întregului upstream). Dacă o cerere MCP "tools/call" apelează
	// un instrument prezent în această hartă, scope-ul lui îl suprascrie
	// pe RequiredScope pentru cererea respectivă — ex. "read_email" poate
	// cere doar tools:email:read, iar "delete_email" poate cere
	// tools:email:delete, chiar dacă ambele trec prin același upstream.
	ToolScopes map[string]string `json:"tool_scopes,omitempty"`
}

// Config este configurația completă a gateway-ului Nexus.
type Config struct {
	// ListenAddr este adresa TCP pe care ascultă gateway-ul, ex: ":8080".
	ListenAddr string `json:"listen_addr"`
	// Upstreams este lista de destinații cunoscute de gateway.
	Upstreams []Upstream `json:"upstreams"`
	// MaxBodyBytes limitează dimensiunea corpului cererilor acceptate,
	// ca primă barieră de protecție împotriva payload-urilor abuzive.
	MaxBodyBytes int64 `json:"max_body_bytes"`
	// ReadHeaderTimeout și ShutdownTimeout controlează robustețea
	// serverului HTTP la cereri lente sau la închidere controlată.
	ReadHeaderTimeoutSeconds int `json:"read_header_timeout_seconds"`
	ShutdownTimeoutSeconds   int `json:"shutdown_timeout_seconds"`

	// TrustDomain este domeniul de încredere SPIFFE al acestei instanțe
	// Nexus, ex. "nexus.trust". Toate identitățile emise și validate sunt
	// legate de acest domeniu.
	TrustDomain string `json:"trust_domain"`
	// AgentsFile este calea către registrul de agenți (configs/agents.json),
	// folosit de endpoint-ul de bootstrap al identității.
	AgentsFile string `json:"agents_file"`
	// DefaultTokenTTLSeconds și MaxTokenTTLSeconds controlează durata de
	// viață a JWT-SVID-urilor emise. Implicit: 5 minute.
	DefaultTokenTTLSeconds int `json:"default_token_ttl_seconds,omitempty"`
	MaxTokenTTLSeconds     int `json:"max_token_ttl_seconds,omitempty"`

	// FinOpsPoliciesFile este calea către politicile financiare per agent
	// (configs/finops_policies.json): buget zilnic și limită de tokeni
	// per sarcină.
	FinOpsPoliciesFile string `json:"finops_policies_file"`

	// ComplianceLedgerFile este calea fișierului WORM (append-only) în
	// care se scrie lanțul tamper-evident de conformitate.
	ComplianceLedgerFile string `json:"compliance_ledger_file"`
	// ComplianceRetentionMonths este politica de retenție declarată,
	// impusă să fie minim 6 — cerința explicită a Articolului 12.
	ComplianceRetentionMonths int `json:"compliance_retention_months"`
	// MaxPromptExcerptBytes limitează câte bytes din corpul cererii sunt
	// copiate ca text lizibil în lanțul de conformitate (digest-ul
	// SHA-256 este mereu integral). 0 = se folosește implicit 4096.
	MaxPromptExcerptBytes int `json:"max_prompt_excerpt_bytes,omitempty"`
}

// ReadHeaderTimeout convertește valoarea din config în time.Duration.
func (c Config) ReadHeaderTimeout() time.Duration {
	if c.ReadHeaderTimeoutSeconds <= 0 {
		return 5 * time.Second
	}
	return time.Duration(c.ReadHeaderTimeoutSeconds) * time.Second
}

// ShutdownTimeout convertește valoarea din config în time.Duration.
func (c Config) ShutdownTimeout() time.Duration {
	if c.ShutdownTimeoutSeconds <= 0 {
		return 10 * time.Second
	}
	return time.Duration(c.ShutdownTimeoutSeconds) * time.Second
}

// DefaultTokenTTL returnează TTL-ul implicit al JWT-SVID-urilor emise.
// Implicit 5 minute.
func (c Config) DefaultTokenTTL() time.Duration {
	if c.DefaultTokenTTLSeconds <= 0 {
		return 5 * time.Minute
	}
	return time.Duration(c.DefaultTokenTTLSeconds) * time.Second
}

// MaxTokenTTL returnează TTL-ul maxim implicit (folosit ca fallback de
// Registry pentru agenții fără max_ttl_seconds propriu).
func (c Config) MaxTokenTTL() time.Duration {
	if c.MaxTokenTTLSeconds <= 0 {
		return c.DefaultTokenTTL()
	}
	return time.Duration(c.MaxTokenTTLSeconds) * time.Second
}

// Load citește și validează un fișier de configurație JSON de pe disc.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: nu pot citi %s: %w", path, err)
	}

	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("config: JSON invalid în %s: %w", path, err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate verifică minimul necesar pentru ca gateway-ul să poată porni
// în siguranță: o adresă de ascultare și cel puțin un upstream valid.
func (c Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("config: listen_addr este obligatoriu")
	}
	if len(c.Upstreams) == 0 {
		return fmt.Errorf("config: este necesar cel puțin un upstream")
	}
	if c.TrustDomain == "" {
		return fmt.Errorf("config: trust_domain este obligatoriu (identitate SPIFFE)")
	}
	if c.AgentsFile == "" {
		return fmt.Errorf("config: agents_file este obligatoriu (registrul de agenți)")
	}
	if c.FinOpsPoliciesFile == "" {
		return fmt.Errorf("config: finops_policies_file este obligatoriu (politici de buget)")
	}
	if c.ComplianceLedgerFile == "" {
		return fmt.Errorf("config: compliance_ledger_file este obligatoriu (registru EU AI Act)")
	}
	if c.ComplianceRetentionMonths < 6 {
		return fmt.Errorf("config: compliance_retention_months trebuie să fie cel puțin 6 (Articolul 12), am primit %d", c.ComplianceRetentionMonths)
	}
	seen := make(map[string]bool, len(c.Upstreams))
	for _, u := range c.Upstreams {
		if u.Name == "" || u.PathPrefix == "" || u.TargetURL == "" {
			return fmt.Errorf("config: upstream invalid (name/path_prefix/target_url lipsă): %+v", u)
		}
		if seen[u.PathPrefix] {
			return fmt.Errorf("config: path_prefix duplicat: %s", u.PathPrefix)
		}
		seen[u.PathPrefix] = true
	}
	return nil
}
