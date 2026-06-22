// validator.go implementează proxy.Validator: respinge automat orice
// cerere care nu prezintă un JWT-SVID valid, semnat de autoritatea
// Nexus, neexpirat și cu scope-ul cerut de ruta apelată. Înlocuiește
// proxy.NoopValidator fără nicio schimbare în pachetul proxy — se
// conectează prin interfața deja pregătită acolo.
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

// SPIFFEValidator verifică identitatea criptografică a agentului care
// face o cerere, pe baza tokenurilor JWT-SVID emise de Issuer.
type SPIFFEValidator struct {
	pub         ed25519.PublicKey
	trustDomain string
	suspension  SuspensionChecker
}

// NewSPIFFEValidator construiește un validator care acceptă doar tokenuri
// semnate cu cheia publică dată și emise pentru domeniul de încredere dat.
// suspension poate fi nil, caz în care se folosește NoopSuspensionChecker
// (niciun agent nu este vreodată suspendat).
func NewSPIFFEValidator(pub ed25519.PublicKey, trustDomain string, suspension SuspensionChecker) *SPIFFEValidator {
	if suspension == nil {
		suspension = NoopSuspensionChecker{}
	}
	return &SPIFFEValidator{pub: pub, trustDomain: trustDomain, suspension: suspension}
}

// Validate implementează proxy.Validator. Cere un antet
// "Authorization: Bearer <jwt-svid>", verifică semnătura și expirarea
// tokenului, verifică domeniul de încredere și, dacă ruta cere un scope
// anume (meta.RequiredScope, populat de proxy din configurația
// upstream-ului), verifică că tokenul îl conține. La succes, scrie
// identitatea verificată înapoi în meta — astfel logging-ul, FinOps și
// conformitatea văd identitatea reală, nu un antet declarat de client
// și potențial falsificat.
func (v *SPIFFEValidator) Validate(_ context.Context, meta *parser.RequestMeta, r *http.Request) error {
	token, err := bearerToken(r)
	if err != nil {
		return err
	}

	claims, err := Verify(v.pub, token)
	if err != nil {
		return err
	}

	// Un agent suspendat de un operator (kill-switch) este respins
	// instantaneu, indiferent cât de valid este criptografic tokenul lui —
	// suspendarea revocă efectiv accesul, nu doar emiterea de tokenuri noi.
	if suspended, reason := v.suspension.IsSuspended(claims.AgentID); suspended {
		return fmt.Errorf("identity: agentul %q este suspendat de un operator (%s) — acces revocat", claims.AgentID, reason)
	}

	expectedPrefix := fmt.Sprintf("spiffe://%s/agent/", v.trustDomain)
	if !strings.HasPrefix(claims.Subject, expectedPrefix) {
		return fmt.Errorf("identity: token emis pentru un domeniu de încredere necunoscut: %s", claims.Subject)
	}

	if meta.RequiredScope != "" && !containsScope(claims.Scopes, meta.RequiredScope) {
		return fmt.Errorf(
			"identity: scope insuficient pentru această rută — necesar %q, token are %v",
			meta.RequiredScope, claims.Scopes,
		)
	}

	// Identitate verificată cu succes: o scriem în meta pentru audit/logging.
	meta.SPIFFEID = claims.Subject
	meta.VerifiedAgentID = claims.AgentID
	meta.VerifiedTaskID = claims.TaskID
	meta.VerifiedScopes = claims.Scopes

	return nil
}

func bearerToken(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", errors.New("identity: antet Authorization absent — niciun JWT-SVID prezentat")
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return "", errors.New(`identity: format Authorization invalid, se așteaptă "Bearer <jwt-svid>"`)
	}
	token := strings.TrimSpace(strings.TrimPrefix(h, prefix))
	if token == "" {
		return "", errors.New("identity: token absent în antetul Authorization")
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
