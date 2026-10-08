// Package identity implements AIMS (Agent Identity Management System) —
// Nexus Trust Protocol's non-human identity engine, inspired by the
// IETF WIMSE and SPIFFE standards. Its goal is to eliminate static API
// keys: instead of a password, an agent gets an ephemeral cryptographic
// identity (JWT-SVID) issued by Nexus, valid for a few minutes and
// strictly scoped to a specific set of tools/permissions.
//
// jwtsvid.go contains the minimal token format used: an Ed25519-signed
// JWT, built with only the standard library (no external JOSE/JWT
// dependencies), to keep the gateway easy to build and audit.
package identity

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"nexus-gateway/internal/keystore"
)

// Algorithm and TokenType identify the token's format in the JWT
// header. "JWT-SVID" explicitly marks this as an SVID (SPIFFE
// Verifiable Identity Document) in JWT form, not a generic application
// JWT.
const (
	Algorithm = "EdDSA"
	TokenType = "JWT-SVID"
)

// header is the standard JWT header.
type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	// Kid identifies the signing key (see keystore.KeyID), so verifiers
	// can pick the right public key during a rotation.
	Kid string `json:"kid,omitempty"`
}

// Claims represents the contents of a JWT-SVID issued by Nexus for an
// AI agent, for a specific task, with an explicit set of scopes
// (permissions to use tools/upstreams).
type Claims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"` // SPIFFE ID: spiffe://<trust-domain>/agent/<agent-id>/task/<task-id>
	ExpiresAt int64  `json:"exp"`
	IssuedAt  int64  `json:"iat"`
	NotBefore int64  `json:"nbf"`
	JTI       string `json:"jti"`

	// AgentID and TaskID are extracted explicitly (in addition to
	// Subject) so the validator and logging can read them directly,
	// without re-parsing the SPIFFE ID every time.
	AgentID string `json:"nexus_agent_id"`
	TaskID  string `json:"nexus_task_id"`
	// Scopes is the strict list of permissions granted to this token —
	// e.g. ["llm:openai:invoke"]. A token without a given scope cannot
	// access the route that requires it, regardless of the agent's
	// identity.
	Scopes []string `json:"nexus_scopes"`
}

// ExpiresAtTime and IssuedAtTime are convenience helpers for code and
// tests, avoiding repeated Unix timestamp conversions.
func (c Claims) ExpiresAtTime() time.Time { return time.Unix(c.ExpiresAt, 0).UTC() }
func (c Claims) IssuedAtTime() time.Time  { return time.Unix(c.IssuedAt, 0).UTC() }

// Sign produces an Ed25519-signed JWT-SVID for the given claims.
func Sign(priv ed25519.PrivateKey, claims Claims) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", errors.New("jwtsvid: invalid Ed25519 private key")
	}

	headerJSON, err := json.Marshal(header{Alg: Algorithm, Typ: TokenType, Kid: keystore.KeyID(priv.Public().(ed25519.PublicKey))})
	if err != nil {
		return "", fmt.Errorf("jwtsvid: cannot serialize header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("jwtsvid: cannot serialize claims: %w", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := headerB64 + "." + claimsB64

	signature := ed25519.Sign(priv, []byte(signingInput))
	sigB64 := base64.RawURLEncoding.EncodeToString(signature)

	return signingInput + "." + sigB64, nil
}

// TokenKeyID returns the kid in the token's header without verifying
// anything ("" if absent or unreadable). The result selects which public
// key to verify with; it is never trusted on its own.
func TokenKeyID(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ""
	}
	var h header
	if json.Unmarshal(raw, &h) != nil {
		return ""
	}
	return h.Kid
}

// Verify validates a JWT-SVID's cryptographic signature and its
// expiration (exp/nbf). It does not validate the trust domain or
// scopes — that's the caller's responsibility (typically
// SPIFFEValidator), which has context about the route being requested.
func Verify(pub ed25519.PublicKey, token string) (Claims, error) {
	var claims Claims

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return claims, errors.New("jwtsvid: invalid token format (expected header.claims.signature)")
	}
	headerB64, claimsB64, sigB64 := parts[0], parts[1], parts[2]

	headerJSON, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return claims, fmt.Errorf("jwtsvid: invalid base64 header: %w", err)
	}
	var hdr header
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return claims, fmt.Errorf("jwtsvid: invalid JSON header: %w", err)
	}
	if hdr.Alg != Algorithm {
		return claims, fmt.Errorf("jwtsvid: unknown or disallowed algorithm: %q", hdr.Alg)
	}

	signature, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return claims, fmt.Errorf("jwtsvid: invalid base64 signature: %w", err)
	}
	signingInput := headerB64 + "." + claimsB64
	if !ed25519.Verify(pub, []byte(signingInput), signature) {
		return claims, errors.New("jwtsvid: invalid signature — token forged or issued by a different authority")
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(claimsB64)
	if err != nil {
		return claims, fmt.Errorf("jwtsvid: invalid base64 claims: %w", err)
	}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return claims, fmt.Errorf("jwtsvid: invalid JSON claims: %w", err)
	}

	now := time.Now().Unix()
	if claims.ExpiresAt != 0 && now >= claims.ExpiresAt {
		return claims, errors.New("jwtsvid: token expired")
	}
	if claims.NotBefore != 0 && now < claims.NotBefore {
		return claims, errors.New("jwtsvid: token not yet valid (nbf is in the future)")
	}

	return claims, nil
}
