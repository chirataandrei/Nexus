// registry.go contains Nexus's registry of known AI agents — the
// equivalent of a list of "workloads" authorized to "bootstrap" (the
// initial exchange of a pre-distributed secret for an ephemeral
// JWT-SVID). In a full SPIFFE deployment, this step would be replaced
// by platform-level attestation (k8s, TPM, etc.); here we use a simple
// bootstrap secret, stored only as a SHA-256 hash.
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

// AgentRecord describes an AI agent registered with Nexus: its
// identity, its bootstrap secret hash, and the maximum scopes it can
// ever request (any request beyond this set is rejected — this is the
// privilege-escalation barrier).
type AgentRecord struct {
	AgentID string `json:"agent_id"`
	// SecretHash is sha256("<agent_id>:<secret>") in hex — never the
	// secret in plaintext. Generate it with cmd/nexus-agentctl.
	SecretHash string `json:"secret_hash"`
	// AllowedScopes is the agent's absolute permission ceiling.
	AllowedScopes []string `json:"allowed_scopes"`
	// MaxTTLSeconds, if set, overrides the registry's default max TTL
	// for this specific agent (e.g. an agent with more sensitive
	// permissions may only get tokens valid for 60s).
	MaxTTLSeconds int `json:"max_ttl_seconds,omitempty"`
}

// MaxTTL returns the maximum lifetime allowed for a token belonging to
// this agent, falling back if the agent has no value of its own.
func (rec AgentRecord) MaxTTL(fallback time.Duration) time.Duration {
	if rec.MaxTTLSeconds > 0 {
		return time.Duration(rec.MaxTTLSeconds) * time.Second
	}
	return fallback
}

// EnsureScopesAllowed checks that no requested scope exceeds
// AllowedScopes — an agent can never obtain, through a token request,
// more permissions than an administrator has explicitly granted it.
func (rec AgentRecord) EnsureScopesAllowed(requested []string) error {
	allowed := make(map[string]bool, len(rec.AllowedScopes))
	for _, s := range rec.AllowedScopes {
		allowed[s] = true
	}
	for _, s := range requested {
		if !allowed[s] {
			return fmt.Errorf(
				"identity: scope %q is not allowed for agent %q (possible privilege escalation rejected)",
				s, rec.AgentID,
			)
		}
	}
	return nil
}

// agentsFile is the on-disk JSON format for the agent registry.
type agentsFile struct {
	DefaultMaxTTLSeconds int           `json:"default_max_ttl_seconds,omitempty"`
	Agents               []AgentRecord `json:"agents"`
}

// Registry holds the registered agents and the default max TTL in
// memory.
type Registry struct {
	agents        map[string]AgentRecord
	defaultMaxTTL time.Duration
}

// LoadRegistry reads a JSON file from disk and builds the agent
// registry. fallbackDefaultMaxTTL is used if the file doesn't specify
// default_max_ttl_seconds.
func LoadRegistry(path string, fallbackDefaultMaxTTL time.Duration) (*Registry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("identity: cannot read agent registry %s: %w", path, err)
	}

	var f agentsFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("identity: invalid JSON in %s: %w", path, err)
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
			return nil, fmt.Errorf("identity: invalid agent (missing agent_id/secret_hash): %+v", a)
		}
		if _, dup := reg.agents[a.AgentID]; dup {
			return nil, fmt.Errorf("identity: duplicate agent_id in registry: %s", a.AgentID)
		}
		reg.agents[a.AgentID] = a
	}

	if len(reg.agents) == 0 {
		return nil, fmt.Errorf("identity: agent registry %s is empty", path)
	}
	return reg, nil
}

// DefaultMaxTTL is the registry's default max TTL (used for agents that
// don't define their own max_ttl_seconds).
func (r *Registry) DefaultMaxTTL() time.Duration {
	return r.defaultMaxTTL
}

// Authenticate checks the (agentID, secret) pair against the registry.
// The comparison is always done via hash + constant-time compare, even
// for nonexistent agents, so there's no observable timing difference
// between "agent doesn't exist" and "wrong secret".
func (r *Registry) Authenticate(agentID, secret string) (AgentRecord, error) {
	rec, found := r.agents[agentID]

	candidate := HashSecret(agentID, secret)
	stored := rec.SecretHash // empty if the agent wasn't found

	match := subtle.ConstantTimeCompare([]byte(candidate), []byte(stored)) == 1

	if !found || !match || stored == "" {
		return AgentRecord{}, fmt.Errorf("identity: authentication failed for agent %q", agentID)
	}
	return rec, nil
}

// HashSecret computes the hash used to store bootstrap secrets. It's
// exported so cmd/nexus-agentctl can use it to generate new entries for
// configs/agents.json.
func HashSecret(agentID, secret string) string {
	sum := sha256.Sum256([]byte(agentID + ":" + secret))
	return hex.EncodeToString(sum[:])
}
