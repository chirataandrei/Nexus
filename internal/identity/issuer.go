// issuer.go contains Nexus's identity-issuing authority: it generates
// the gateway's Ed25519 key pair (the equivalent of a minimal,
// self-contained SPIRE Server) and issues ephemeral JWT-SVIDs for
// agents, strictly tied to an agent_id, a task_id, and an explicit set
// of scopes.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"time"

	"nexus-gateway/internal/keystore"
)

// Issuer is the identity authority of a Nexus instance for a single
// SPIFFE trust domain.
type Issuer struct {
	priv        ed25519.PrivateKey
	pub         ed25519.PublicKey
	trustDomain string
	defaultTTL  time.Duration
}

// NewIssuer generates a new Ed25519 key pair and builds an Issuer for
// the given trust domain.
//
// This variant keeps the key in memory only (tests, throwaway runs);
// restarting invalidates every issued token. The gateway itself uses
// NewIssuerWithKey with a key persisted by internal/keystore.
func NewIssuer(trustDomain string, defaultTTL time.Duration) (*Issuer, error) {
	if trustDomain == "" {
		return nil, fmt.Errorf("identity: trust_domain is required")
	}
	if defaultTTL <= 0 {
		defaultTTL = 5 * time.Minute
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("identity: cannot generate the authority's Ed25519 key: %w", err)
	}

	return &Issuer{priv: priv, pub: pub, trustDomain: trustDomain, defaultTTL: defaultTTL}, nil
}

// NewIssuerWithKey builds an Issuer around a persisted key (see
// keystore.LoadOrCreate), so tokens stay valid across restarts and the
// key can be rotated deliberately.
func NewIssuerWithKey(trustDomain string, defaultTTL time.Duration, priv ed25519.PrivateKey) (*Issuer, error) {
	if trustDomain == "" {
		return nil, fmt.Errorf("identity: trust_domain is required")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("identity: invalid Ed25519 private key")
	}
	if defaultTTL <= 0 {
		defaultTTL = 5 * time.Minute
	}
	return &Issuer{priv: priv, pub: priv.Public().(ed25519.PublicKey), trustDomain: trustDomain, defaultTTL: defaultTTL}, nil
}

// KeyID returns the kid stamped on every token this issuer signs.
func (iss *Issuer) KeyID() string { return keystore.KeyID(iss.pub) }

// PublicKey returns the authority's public key, used by SPIFFEValidator
// to verify token signatures.
func (iss *Issuer) PublicKey() ed25519.PublicKey { return iss.pub }

// TrustDomain returns the configured trust domain.
func (iss *Issuer) TrustDomain() string { return iss.trustDomain }

// DefaultTTL returns the default TTL used when none is explicitly
// requested.
func (iss *Issuer) DefaultTTL() time.Duration { return iss.defaultTTL }

// IssueSVID issues a new JWT-SVID for the given agent and task, with
// exactly the scopes provided (no more — the caller, typically
// TokenHandler, is responsible for validating them against
// AllowedScopes before calling this function).
func (iss *Issuer) IssueSVID(agentID, taskID string, scopes []string, ttl time.Duration) (string, Claims, error) {
	if agentID == "" || taskID == "" {
		return "", Claims{}, fmt.Errorf("identity: agent_id and task_id are required to issue a JWT-SVID")
	}
	if ttl <= 0 {
		ttl = iss.defaultTTL
	}

	jti, err := newJTI()
	if err != nil {
		return "", Claims{}, err
	}

	now := time.Now().UTC()
	claims := Claims{
		Issuer:    "nexus-trust-protocol",
		Subject:   fmt.Sprintf("spiffe://%s/agent/%s/task/%s", iss.trustDomain, agentID, taskID),
		ExpiresAt: now.Add(ttl).Unix(),
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
		JTI:       jti,
		AgentID:   agentID,
		TaskID:    taskID,
		Scopes:    scopes,
	}

	token, err := Sign(iss.priv, claims)
	if err != nil {
		return "", Claims{}, err
	}
	return token, claims, nil
}
