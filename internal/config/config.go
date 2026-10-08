// Package config loads the Nexus Trust Protocol gateway's
// configuration: the address the server listens on and the list of
// upstreams (LLM models, internal services) requests are routed to,
// based on path prefix. The format is plain JSON, with no external
// dependencies, to keep the gateway buildable with just the Go standard
// library.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Upstream describes a destination Nexus can route traffic to: an
// external LLM model (OpenAI, Anthropic) or an internal company service
// (database, in-house API).
type Upstream struct {
	// Name is the upstream's internal identifier, used in logs and in
	// budget/compliance policies.
	Name string `json:"name"`
	// PathPrefix is the URL prefix Nexus intercepts, e.g. "/v1/openai"
	// or "/v1/anthropic".
	PathPrefix string `json:"path_prefix"`
	// TargetURL is the upstream's real address the proxy forwards to.
	TargetURL string `json:"target_url"`
	// StripPrefix, if true, removes PathPrefix from the path before
	// sending the request to TargetURL (useful when the upstream doesn't
	// know about the internal prefix Nexus uses).
	StripPrefix bool `json:"strip_prefix"`
	// RequiredScope, if set, requires every request to this upstream to
	// present a JWT-SVID containing exactly this scope. Empty = any valid
	// identity is enough, with no scope restriction on this route.
	RequiredScope string `json:"required_scope,omitempty"`
	// PricePerThousandTokensUSD is the price FinOps uses to calculate the
	// real cost of calls to this upstream, based on the "usage" field in
	// the LLM model's response. 0 = this upstream isn't billed per token
	// (e.g. an internal tool).
	PricePerThousandTokensUSD float64 `json:"price_per_1k_tokens_usd,omitempty"`
	// ToolScopes maps the name of an MCP tool (e.g. "send_email") to the
	// scope required for EXACTLY that tool, finer-grained than
	// RequiredScope (which applies to the whole upstream). If an MCP
	// "tools/call" request calls a tool present in this map, that tool's
	// scope overrides RequiredScope for that specific request — e.g.
	// "read_email" may only require tools:email:read, while
	// "delete_email" may require tools:email:delete, even though both go
	// through the same upstream.
	ToolScopes map[string]string `json:"tool_scopes,omitempty"`
}

// FailClosed reports whether a request that can't be audited is refused
// (the default) rather than forwarded.
func (c Config) FailClosed() bool {
	return c.ComplianceFailClosed == nil || *c.ComplianceFailClosed
}

// Config is the gateway's complete configuration.
type Config struct {
	// ListenAddr is the TCP address the gateway listens on, e.g. ":8080".
	ListenAddr string `json:"listen_addr"`
	// Upstreams is the list of destinations known to the gateway.
	Upstreams []Upstream `json:"upstreams"`
	// MaxBodyBytes limits the size of accepted request bodies, as a
	// first line of defense against abusive payloads.
	MaxBodyBytes int64 `json:"max_body_bytes"`
	// ReadHeaderTimeout and ShutdownTimeout control the HTTP server's
	// resilience to slow requests and its controlled shutdown.
	ReadHeaderTimeoutSeconds int `json:"read_header_timeout_seconds"`
	ShutdownTimeoutSeconds   int `json:"shutdown_timeout_seconds"`

	// TrustDomain is this Nexus instance's SPIFFE trust domain, e.g.
	// "nexus.trust". Every identity issued and validated is tied to this
	// domain.
	TrustDomain string `json:"trust_domain"`
	// AgentsFile is the path to the agent registry (configs/agents.json),
	// used by the identity bootstrap endpoint.
	AgentsFile string `json:"agents_file"`
	// DefaultTokenTTLSeconds and MaxTokenTTLSeconds control the lifetime
	// of issued JWT-SVIDs. Default: 5 minutes.
	DefaultTokenTTLSeconds int `json:"default_token_ttl_seconds,omitempty"`
	MaxTokenTTLSeconds     int `json:"max_token_ttl_seconds,omitempty"`

	// IdentityKeyFile is where the token-signing Ed25519 key is persisted
	// (created on first start, mode 0600). The kid in every token points
	// at it, so tokens survive restarts and the key can be rotated.
	IdentityKeyFile string `json:"identity_key_file"`
	// IdentityRetiredKeysFile optionally lists public keys of rotated-out
	// identity keys ({"<kid>": "<base64 pub>"}) still accepted for tokens
	// issued before the rotation.
	IdentityRetiredKeysFile string `json:"identity_retired_keys_file,omitempty"`
	// TokenMaxFailuresPerIP / TokenMaxFailuresPerAgent / TokenFailureWindowSeconds
	// tune the brute-force limits on the token endpoint (0 = defaults).
	TokenMaxFailuresPerIP     int `json:"token_max_failures_per_ip,omitempty"`
	TokenMaxFailuresPerAgent  int `json:"token_max_failures_per_agent,omitempty"`
	TokenFailureWindowSeconds int `json:"token_failure_window_seconds,omitempty"`

	// AdminTokenSHA256 is the hex SHA-256 of the admin token required by
	// /nexus/control/* and /nexus/finops/policies (see nexus-agentctl
	// -gen-admin-token).
	AdminTokenSHA256 string `json:"admin_token_sha256"`

	// FinOpsPoliciesFile is the path to the per-agent financial policies
	// (configs/finops_policies.json): daily budget and per-task token
	// limit.
	FinOpsPoliciesFile string `json:"finops_policies_file"`

	// ComplianceLedgerFile is the path to the WORM (append-only) file the
	// tamper-evident compliance chain is written to.
	ComplianceLedgerFile string `json:"compliance_ledger_file"`
	// ComplianceRetentionMonths is the declared retention policy,
	// required to be at least 6 — the explicit requirement of Article 12.
	ComplianceRetentionMonths int `json:"compliance_retention_months"`
	// ComplianceFailClosed: if true, a request whose audit record can't be
	// written is refused with 503 instead of being forwarded un-audited.
	// Default true (fail-closed): a compliance gateway should not forward
	// calls it could not record. Set false to prefer availability — see
	// docs/THREAT_MODEL.md for the trade-off. A pointer so "unset" and
	// "false" can be told apart.
	ComplianceFailClosed *bool `json:"compliance_fail_closed,omitempty"`
	// PublicUsageEndpoint: if true, GET /nexus/finops/usage needs no admin
	// token. Default false — it exposes per-agent spend and task IDs.
	PublicUsageEndpoint bool `json:"public_usage_endpoint,omitempty"`
	// ComplianceAnchorFile is where signed ledger anchors are appended.
	// Empty disables anchoring. Put it on a different volume than the
	// ledger so one compromise doesn't cover both.
	ComplianceAnchorFile string `json:"compliance_anchor_file,omitempty"`
	// ComplianceAnchorKeyFile is the Ed25519 key signing anchors; kept
	// separate from the identity key (created on first start).
	ComplianceAnchorKeyFile string `json:"compliance_anchor_key_file,omitempty"`
	// ComplianceAnchorRetiredKeysFile: rotated-out anchor public keys.
	ComplianceAnchorRetiredKeysFile string `json:"compliance_anchor_retired_keys_file,omitempty"`
	// ComplianceAnchorEveryRecords / ComplianceAnchorIntervalSeconds:
	// anchor after this many records and at least this often (0 = 100 / 60s).
	ComplianceAnchorEveryRecords    int `json:"compliance_anchor_every_records,omitempty"`
	ComplianceAnchorIntervalSeconds int `json:"compliance_anchor_interval_seconds,omitempty"`
	// MaxPromptExcerptBytes limits how many bytes of the request body are
	// copied as readable text into the compliance chain (the SHA-256
	// digest is always full). 0 = defaults to 4096.
	MaxPromptExcerptBytes int `json:"max_prompt_excerpt_bytes,omitempty"`
}

// ReadHeaderTimeout converts the config value to a time.Duration.
func (c Config) ReadHeaderTimeout() time.Duration {
	if c.ReadHeaderTimeoutSeconds <= 0 {
		return 5 * time.Second
	}
	return time.Duration(c.ReadHeaderTimeoutSeconds) * time.Second
}

// ShutdownTimeout converts the config value to a time.Duration.
func (c Config) ShutdownTimeout() time.Duration {
	if c.ShutdownTimeoutSeconds <= 0 {
		return 10 * time.Second
	}
	return time.Duration(c.ShutdownTimeoutSeconds) * time.Second
}

// DefaultTokenTTL returns the default lifetime of issued JWT-SVIDs.
// Defaults to 5 minutes.
func (c Config) DefaultTokenTTL() time.Duration {
	if c.DefaultTokenTTLSeconds <= 0 {
		return 5 * time.Minute
	}
	return time.Duration(c.DefaultTokenTTLSeconds) * time.Second
}

// MaxTokenTTL returns the default maximum TTL (used as a fallback by
// Registry for agents without their own max_ttl_seconds).
func (c Config) MaxTokenTTL() time.Duration {
	if c.MaxTokenTTLSeconds <= 0 {
		return c.DefaultTokenTTL()
	}
	return time.Duration(c.MaxTokenTTLSeconds) * time.Second
}

// AnchorEvery and AnchorInterval return the anchoring cadence.
func (c Config) AnchorEvery() int {
	if c.ComplianceAnchorEveryRecords <= 0 {
		return 100
	}
	return c.ComplianceAnchorEveryRecords
}

func (c Config) AnchorInterval() time.Duration {
	if c.ComplianceAnchorIntervalSeconds <= 0 {
		return time.Minute
	}
	return time.Duration(c.ComplianceAnchorIntervalSeconds) * time.Second
}

// Load reads and validates a JSON configuration file from disk.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: cannot read %s: %w", path, err)
	}

	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("config: invalid JSON in %s: %w", path, err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate checks the minimum needed for the gateway to start safely:
// a listen address and at least one valid upstream.
func (c Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("config: listen_addr is required")
	}
	if len(c.Upstreams) == 0 {
		return fmt.Errorf("config: at least one upstream is required")
	}
	if c.TrustDomain == "" {
		return fmt.Errorf("config: trust_domain is required (SPIFFE identity)")
	}
	if c.AgentsFile == "" {
		return fmt.Errorf("config: agents_file is required (agent registry)")
	}
	if c.IdentityKeyFile == "" {
		return fmt.Errorf("config: identity_key_file is required (persisted token-signing key)")
	}
	if len(c.AdminTokenSHA256) != 64 {
		return fmt.Errorf("config: admin_token_sha256 is required (64 hex chars; generate with nexus-agentctl -gen-admin-token)")
	}
	if c.MaxTokenTTLSeconds > 24*60*60 || c.DefaultTokenTTLSeconds > 24*60*60 {
		return fmt.Errorf("config: token TTLs cannot exceed 24h (the revocation list's retention)")
	}
	if c.ComplianceAnchorFile != "" && c.ComplianceAnchorKeyFile == "" {
		return fmt.Errorf("config: compliance_anchor_key_file is required when compliance_anchor_file is set")
	}
	if c.FinOpsPoliciesFile == "" {
		return fmt.Errorf("config: finops_policies_file is required (budget policies)")
	}
	if c.ComplianceLedgerFile == "" {
		return fmt.Errorf("config: compliance_ledger_file is required (EU AI Act ledger)")
	}
	if c.ComplianceRetentionMonths < 6 {
		return fmt.Errorf("config: compliance_retention_months must be at least 6 (Article 12), got %d", c.ComplianceRetentionMonths)
	}
	seen := make(map[string]bool, len(c.Upstreams))
	for _, u := range c.Upstreams {
		if u.Name == "" || u.PathPrefix == "" || u.TargetURL == "" {
			return fmt.Errorf("config: invalid upstream (missing name/path_prefix/target_url): %+v", u)
		}
		if seen[u.PathPrefix] {
			return fmt.Errorf("config: duplicate path_prefix: %s", u.PathPrefix)
		}
		seen[u.PathPrefix] = true
	}
	return nil
}
