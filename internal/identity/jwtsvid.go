// Package identity implementează AIMS (Agent Identity Management System) —
// motorul de identitate non-umană al Nexus Trust Protocol, inspirat de
// standardele IETF WIMSE și SPIFFE. Scopul lui este să elimine cheile API
// statice: un agent primește, în locul unei parole, o identitate
// criptografică efemeră (JWT-SVID) emisă de Nexus, valabilă câteva minute
// și limitată strict la un anumit set de scope-uri/instrumente.
//
// jwtsvid.go conține formatul minim de token folosit: un JWT semnat
// Ed25519, construit doar cu biblioteca standard (fără dependențe externe
// de tip JOSE/JWT), pentru a păstra gateway-ul ușor de compilat și auditat.
package identity

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Algorithm și TokenType identifică formatul tokenului în antetul JWT.
// "JWT-SVID" marchează explicit că acesta este un SVID (SPIFFE Verifiable
// Identity Document) sub formă de JWT, nu un JWT generic de aplicație.
const (
	Algorithm = "EdDSA"
	TokenType = "JWT-SVID"
)

// header este antetul standard JWT.
type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// Claims reprezintă conținutul unui JWT-SVID emis de Nexus pentru un
// agent IA, pentru o sarcină (task) anume, cu un set explicit de
// scope-uri (drepturi de utilizare a instrumentelor/upstream-urilor).
type Claims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"` // SPIFFE ID: spiffe://<trust-domain>/agent/<agent-id>/task/<task-id>
	ExpiresAt int64  `json:"exp"`
	IssuedAt  int64  `json:"iat"`
	NotBefore int64  `json:"nbf"`
	JTI       string `json:"jti"`

	// AgentID și TaskID sunt extrase explicit (în plus față de Subject)
	// pentru a fi citite direct de validator și de jurnalizare, fără a
	// re-parsa SPIFFE ID-ul de fiecare dată.
	AgentID string `json:"nexus_agent_id"`
	TaskID  string `json:"nexus_task_id"`
	// Scopes este lista strictă de drepturi acordate acestui token —
	// ex. ["llm:openai:invoke"]. Un token fără un scope nu poate accesa
	// ruta care îl cere, indiferent de identitatea agentului.
	Scopes []string `json:"nexus_scopes"`
}

// ExpiresAtTime și IssuedAtTime sunt utilitare de conveniență pentru cod
// și teste, evitând conversii repetate din Unix timestamp.
func (c Claims) ExpiresAtTime() time.Time { return time.Unix(c.ExpiresAt, 0).UTC() }
func (c Claims) IssuedAtTime() time.Time  { return time.Unix(c.IssuedAt, 0).UTC() }

// Sign produce un JWT-SVID semnat Ed25519 pentru claims-urile date.
func Sign(priv ed25519.PrivateKey, claims Claims) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", errors.New("jwtsvid: cheie privată Ed25519 invalidă")
	}

	headerJSON, err := json.Marshal(header{Alg: Algorithm, Typ: TokenType})
	if err != nil {
		return "", fmt.Errorf("jwtsvid: nu pot serializa antetul: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("jwtsvid: nu pot serializa claims: %w", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := headerB64 + "." + claimsB64

	signature := ed25519.Sign(priv, []byte(signingInput))
	sigB64 := base64.RawURLEncoding.EncodeToString(signature)

	return signingInput + "." + sigB64, nil
}

// Verify validează semnătura criptografică a unui JWT-SVID și expirarea
// lui (exp/nbf). Nu validează domeniul de încredere sau scope-urile —
// acestea sunt responsabilitatea apelantului (de regulă, SPIFFEValidator),
// care are context despre ruta cerută.
func Verify(pub ed25519.PublicKey, token string) (Claims, error) {
	var claims Claims

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return claims, errors.New("jwtsvid: format token invalid (se așteaptă header.claims.semnătură)")
	}
	headerB64, claimsB64, sigB64 := parts[0], parts[1], parts[2]

	headerJSON, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return claims, fmt.Errorf("jwtsvid: antet invalid base64: %w", err)
	}
	var hdr header
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return claims, fmt.Errorf("jwtsvid: antet JSON invalid: %w", err)
	}
	if hdr.Alg != Algorithm {
		return claims, fmt.Errorf("jwtsvid: algoritm necunoscut sau nepermis: %q", hdr.Alg)
	}

	signature, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return claims, fmt.Errorf("jwtsvid: semnătură invalidă base64: %w", err)
	}
	signingInput := headerB64 + "." + claimsB64
	if !ed25519.Verify(pub, []byte(signingInput), signature) {
		return claims, errors.New("jwtsvid: semnătură invalidă — token falsificat sau emis de altă autoritate")
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(claimsB64)
	if err != nil {
		return claims, fmt.Errorf("jwtsvid: claims invalide base64: %w", err)
	}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return claims, fmt.Errorf("jwtsvid: claims JSON invalide: %w", err)
	}

	now := time.Now().Unix()
	if claims.ExpiresAt != 0 && now >= claims.ExpiresAt {
		return claims, errors.New("jwtsvid: token expirat")
	}
	if claims.NotBefore != 0 && now < claims.NotBefore {
		return claims, errors.New("jwtsvid: token nu este încă valid (nbf în viitor)")
	}

	return claims, nil
}
