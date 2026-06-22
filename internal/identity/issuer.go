// issuer.go conține autoritatea de emitere a identităților din Nexus:
// generează perechea de chei Ed25519 a gateway-ului (echivalentul unui
// SPIRE Server minimalist, auto-conținut) și emite JWT-SVID-uri efemere
// pentru agenți, strict legate de un agent_id, un task_id și un set de
// scope-uri explicite.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"time"
)

// Issuer este autoritatea de identitate a unei instanțe Nexus pentru un
// singur domeniu de încredere (trust domain) SPIFFE.
type Issuer struct {
	priv        ed25519.PrivateKey
	pub         ed25519.PublicKey
	trustDomain string
	defaultTTL  time.Duration
}

// NewIssuer generează o pereche de chei Ed25519 nouă și construiește un
// Issuer pentru domeniul de încredere dat.
//
// Notă de securitate: cheia este generată în memorie la pornirea
// procesului și nu este persistată — un restart al gateway-ului
// invalidează implicit toate tokenurile emise anterior (acceptabil, dat
// fiind TTL-ul de ordinul minutelor). Într-o implementare de producție,
// această cheie ar fi gestionată de o autoritate dedicată (ex. SPIRE
// Server) cu rotație și federare reală.
func NewIssuer(trustDomain string, defaultTTL time.Duration) (*Issuer, error) {
	if trustDomain == "" {
		return nil, fmt.Errorf("identity: trust_domain este obligatoriu")
	}
	if defaultTTL <= 0 {
		defaultTTL = 5 * time.Minute
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("identity: nu pot genera cheia Ed25519 a autorității: %w", err)
	}

	return &Issuer{priv: priv, pub: pub, trustDomain: trustDomain, defaultTTL: defaultTTL}, nil
}

// PublicKey returnează cheia publică a autorității, folosită de
// SPIFFEValidator pentru a verifica semnătura tokenurilor.
func (iss *Issuer) PublicKey() ed25519.PublicKey { return iss.pub }

// TrustDomain returnează domeniul de încredere configurat.
func (iss *Issuer) TrustDomain() string { return iss.trustDomain }

// DefaultTTL returnează TTL-ul implicit folosit când nu se cere unul explicit.
func (iss *Issuer) DefaultTTL() time.Duration { return iss.defaultTTL }

// IssueSVID emite un JWT-SVID nou pentru agentul și sarcina date, cu
// exact scope-urile primite (nu mai multe — apelantul, de regulă
// TokenHandler, este responsabil să le valideze față de AllowedScopes
// înainte de a apela această funcție).
func (iss *Issuer) IssueSVID(agentID, taskID string, scopes []string, ttl time.Duration) (string, Claims, error) {
	if agentID == "" || taskID == "" {
		return "", Claims{}, fmt.Errorf("identity: agent_id și task_id sunt obligatorii pentru emiterea unui JWT-SVID")
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
