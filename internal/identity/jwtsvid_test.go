package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func generateTestKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("nu pot genera cheia de test: %v", err)
	}
	return pub, priv
}

func TestSignAndVerify_RoundTrip(t *testing.T) {
	pub, priv := generateTestKeypair(t)
	now := time.Now().UTC()

	claims := Claims{
		Issuer:    "nexus-trust-protocol",
		Subject:   "spiffe://nexus.trust/agent/agent-1/task/task-1",
		ExpiresAt: now.Add(5 * time.Minute).Unix(),
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
		JTI:       "test-jti",
		AgentID:   "agent-1",
		TaskID:    "task-1",
		Scopes:    []string{"llm:openai:invoke"},
	}

	token, err := Sign(priv, claims)
	if err != nil {
		t.Fatalf("Sign a eșuat: %v", err)
	}

	got, err := Verify(pub, token)
	if err != nil {
		t.Fatalf("Verify a eșuat pe un token valid: %v", err)
	}
	if got.Subject != claims.Subject || got.AgentID != claims.AgentID {
		t.Errorf("claims decodate diferă de original: %+v", got)
	}
}

func TestVerify_RejectsTamperedSignature(t *testing.T) {
	pub, priv := generateTestKeypair(t)
	now := time.Now().UTC()
	claims := Claims{
		Subject:   "spiffe://nexus.trust/agent/agent-1/task/task-1",
		ExpiresAt: now.Add(5 * time.Minute).Unix(),
	}
	token, err := Sign(priv, claims)
	if err != nil {
		t.Fatalf("Sign a eșuat: %v", err)
	}

	tampered := token[:len(token)-2] + "xx"
	if _, err := Verify(pub, tampered); err == nil {
		t.Error("Verify ar trebui să respingă o semnătură falsificată")
	}
}

func TestVerify_RejectsWrongKey(t *testing.T) {
	_, priv := generateTestKeypair(t)
	otherPub, _ := generateTestKeypair(t)

	now := time.Now().UTC()
	token, err := Sign(priv, Claims{Subject: "spiffe://nexus.trust/agent/x/task/y", ExpiresAt: now.Add(time.Minute).Unix()})
	if err != nil {
		t.Fatalf("Sign a eșuat: %v", err)
	}

	if _, err := Verify(otherPub, token); err == nil {
		t.Error("Verify ar trebui să respingă un token semnat cu altă cheie")
	}
}

func TestVerify_RejectsExpiredToken(t *testing.T) {
	pub, priv := generateTestKeypair(t)
	now := time.Now().UTC()
	token, err := Sign(priv, Claims{
		Subject:   "spiffe://nexus.trust/agent/x/task/y",
		IssuedAt:  now.Add(-10 * time.Minute).Unix(),
		ExpiresAt: now.Add(-5 * time.Minute).Unix(), // expirat în trecut
	})
	if err != nil {
		t.Fatalf("Sign a eșuat: %v", err)
	}

	if _, err := Verify(pub, token); err == nil {
		t.Error("Verify ar trebui să respingă un token expirat")
	}
}

func TestVerify_RejectsNotYetValidToken(t *testing.T) {
	pub, priv := generateTestKeypair(t)
	now := time.Now().UTC()
	token, err := Sign(priv, Claims{
		Subject:   "spiffe://nexus.trust/agent/x/task/y",
		NotBefore: now.Add(10 * time.Minute).Unix(), // valabil abia în viitor
		ExpiresAt: now.Add(20 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("Sign a eșuat: %v", err)
	}

	if _, err := Verify(pub, token); err == nil {
		t.Error("Verify ar trebui să respingă un token cu nbf în viitor")
	}
}

func TestVerify_RejectsMalformedToken(t *testing.T) {
	pub, _ := generateTestKeypair(t)
	if _, err := Verify(pub, "nu-este-un-jwt"); err == nil {
		t.Error("Verify ar trebui să respingă un token malformat")
	}
}
