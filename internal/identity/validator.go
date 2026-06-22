// validator.go implements proxy.Validator: it automatically rejects any
// request that doesn't present a valid JWT-SVID, signed by the Nexus
// authority, not expired, and with the scope the called route requires.
// It replaces proxy.NoopValidator with no changes to the proxy package
// — it plugs in through the interface already prepared there.
package identity

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"nexus-gateway/internal/parser"
)

// SPIFFEValidator verifies the cryptographic identity of the agent
// making a request, based on JWT-SVID tokens issued by Issuer.
type SPIFFEValidator struct {
	pub         ed25519.PublicKey
	trustDomain string
	suspension  SuspensionChecker
}

// NewSPIFFEValidator builds a validator that only accepts tokens signed
// with the given public key and issued for the given trust domain.
// suspension may be nil, in which case NoopSuspensionChecker is used
// (no agent is ever suspended).
func NewSPIFFEValidator(pub ed25519.PublicKey, trustDomain string, suspension SuspensionChecker) *SPIFFEValidator {
	if suspension == nil {
		suspension = NoopSuspensionChecker{}
	}
	return &SPIFFEValidator{pub: pub, trustDomain: trustDomain, suspension: suspension}
}

// Validate implements proxy.Validator. It requires an
// "Authorization: Bearer <jwt-svid>" header, verifies the token's
// signature and expiration, checks the trust domain, and, if the route
// requires a specific scope (meta.RequiredScope, populated by the proxy
// from the upstream's configuration), verifies the token contains it.
// On success, it writes the verified identity back into meta — so
// logging, FinOps, and compliance all see the real identity, not a
// client-declared header that could be forged.
func (v *SPIFFEValidator) Validate(_ context.Context, meta *parser.RequestMeta, r *http.Request) error {
	token, err := bearerToken(r)
	if err != nil {
		return err
	}

	claims, err := Verify(v.pub, token)
	if err != nil {
		return err
	}

	// An agent suspended by an operator (kill switch) is rejected
	// instantly, no matter how cryptographically valid its token is —
	// suspension effectively revokes access, not just the issuing of new
	// tokens.
	if suspended, reason := v.suspension.IsSuspended(claims.AgentID); suspended {
		return fmt.Errorf("identity: agent %q is suspended by an operator (%s) — access revoked", claims.AgentID, reason)
	}

	expectedPrefix := fmt.Sprintf("spiffe://%s/agent/", v.trustDomain)
	if !strings.HasPrefix(claims.Subject, expectedPrefix) {
		return fmt.Errorf("identity: token issued for an unknown trust domain: %s", claims.Subject)
	}

	if meta.RequiredScope != "" && !containsScope(claims.Scopes, meta.RequiredScope) {
		return fmt.Errorf(
			"identity: insufficient scope for this route — required %q, token has %v",
			meta.RequiredScope, claims.Scopes,
		)
	}

	// Identity successfully verified: write it into meta for audit/logging.
	meta.SPIFFEID = claims.Subject
	meta.VerifiedAgentID = claims.AgentID
	meta.VerifiedTaskID = claims.TaskID
	meta.VerifiedScopes = claims.Scopes

	return nil
}

func bearerToken(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", errors.New("identity: Authorization header missing — no JWT-SVID presented")
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return "", errors.New(`identity: invalid Authorization format, expected "Bearer <jwt-svid>"`)
	}
	token := strings.TrimSpace(strings.TrimPrefix(h, prefix))
	if token == "" {
		return "", errors.New("identity: token missing from the Authorization header")
	}
	return token, nil
}

func containsScope(scopes []string, required string) bool {
	for _, s := range scopes {
		if s == required {
			return true
		}
	}
	return false
}
