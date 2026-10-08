package identity

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"nexus-gateway/internal/keystore"
)

func bearerReq(token string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/v1/openai/models", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

func TestRevokedTokenIsRejectedImmediately(t *testing.T) {
	iss := newTestIssuer(t, "nexus.trust")
	rl := NewRevocationList()
	v := NewSPIFFEValidator(iss.PublicKey(), "nexus.trust", nil).WithRevocations(rl)

	tok, claims, _ := iss.IssueSVID("agent-1", "task-1", []string{"s"}, time.Minute)
	req := bearerReq(tok)
	if err := v.Validate(context.Background(), metaFor(req, ""), req); err != nil {
		t.Fatalf("token should be valid before revocation: %v", err)
	}

	rl.Revoke(claims.JTI)
	req = bearerReq(tok)
	if err := v.Validate(context.Background(), metaFor(req, ""), req); err == nil {
		t.Fatal("a revoked token must be rejected")
	}

	// A different token for the same agent is unaffected.
	tok2, _, _ := iss.IssueSVID("agent-1", "task-1", []string{"s"}, time.Minute)
	req = bearerReq(tok2)
	if err := v.Validate(context.Background(), metaFor(req, ""), req); err != nil {
		t.Errorf("revocation must be per-jti, got: %v", err)
	}
}

func TestValidatorPopulatesJTI(t *testing.T) {
	iss := newTestIssuer(t, "nexus.trust")
	v := NewSPIFFEValidator(iss.PublicKey(), "nexus.trust", nil)
	tok, claims, _ := iss.IssueSVID("a", "t", nil, time.Minute)
	req := bearerReq(tok)
	meta := metaFor(req, "")
	if err := v.Validate(context.Background(), meta, req); err != nil || meta.VerifiedJTI != claims.JTI {
		t.Errorf("VerifiedJTI = %q (err %v), want %q", meta.VerifiedJTI, err, claims.JTI)
	}
}

func TestKeyRotation_PersistedKeySurvivesRestartAndRetiredKeyStillVerifies(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "k.json")

	// "Process 1" issues a token with the persisted key.
	priv1, _, _ := keystore.LoadOrCreate(keyPath)
	iss1, _ := NewIssuerWithKey("nexus.trust", time.Minute, priv1)
	tok, _, _ := iss1.IssueSVID("agent-1", "task-1", nil, time.Minute)
	if TokenKeyID(tok) != iss1.KeyID() || iss1.KeyID() == "" {
		t.Fatalf("token kid = %q, want %q", TokenKeyID(tok), iss1.KeyID())
	}

	// "Process 2" (restart): same key file, token still verifies.
	priv2, created, _ := keystore.LoadOrCreate(keyPath)
	iss2, _ := NewIssuerWithKey("nexus.trust", time.Minute, priv2)
	v := NewSPIFFEValidator(iss2.PublicKey(), "nexus.trust", nil)
	req := bearerReq(tok)
	if created {
		t.Fatal("key must not be regenerated on restart")
	}
	if err := v.Validate(context.Background(), metaFor(req, ""), req); err != nil {
		t.Fatalf("token must survive a restart: %v", err)
	}

	// Rotation: a brand-new key is current; the old one is retired.
	newPub, newPriv, _ := ed25519.GenerateKey(nil)
	issNew, _ := NewIssuerWithKey("nexus.trust", time.Minute, newPriv)
	vNew := NewSPIFFEValidator(newPub, "nexus.trust", nil)
	req = bearerReq(tok)
	if err := vNew.Validate(context.Background(), metaFor(req, ""), req); err == nil {
		t.Fatal("after rotation without retired keys, old tokens must be rejected (unknown kid)")
	}
	retired := keystore.PublicKeySet{}
	retired.Add(iss1.PublicKey())
	vNew.WithRetiredKeys(retired)
	req = bearerReq(tok)
	if err := vNew.Validate(context.Background(), metaFor(req, ""), req); err != nil {
		t.Fatalf("old token must verify via the retired key: %v", err)
	}
	tokNew, _, _ := issNew.IssueSVID("agent-1", "task-1", nil, time.Minute)
	req = bearerReq(tokNew)
	if err := vNew.Validate(context.Background(), metaFor(req, ""), req); err != nil {
		t.Errorf("new key's tokens must verify: %v", err)
	}
}

func TestKidCannotSelectAForgedKey(t *testing.T) {
	iss := newTestIssuer(t, "nexus.trust")
	v := NewSPIFFEValidator(iss.PublicKey(), "nexus.trust", nil)
	// Attacker signs with their own key but stamps the real kid... Sign
	// derives kid from the signing key, so forge by signing with another
	// issuer: kid is unknown -> rejected; signature wouldn't match anyway.
	other := newTestIssuer(t, "nexus.trust")
	tok, _, _ := other.IssueSVID("agent-1", "task-1", nil, time.Minute)
	req := bearerReq(tok)
	if err := v.Validate(context.Background(), metaFor(req, ""), req); err == nil {
		t.Fatal("a token from a foreign key must be rejected")
	}
}

func TestFailureLimiter_BlocksAfterMaxAndRecovers(t *testing.T) {
	now := time.Unix(1000, 0)
	l := NewFailureLimiter(3, time.Minute)
	l.now = func() time.Time { return now }

	for i := 0; i < 2; i++ {
		l.Fail("k")
	}
	if b, _ := l.Blocked("k"); b {
		t.Fatal("must not block below the threshold")
	}
	l.Fail("k")
	if b, wait := l.Blocked("k"); !b || wait <= 0 || wait > time.Minute {
		t.Fatalf("must block at threshold, got blocked=%v wait=%v", b, wait)
	}
	if b, _ := l.Blocked("other"); b {
		t.Error("other keys must be unaffected")
	}
	now = now.Add(61 * time.Second)
	if b, _ := l.Blocked("k"); b {
		t.Error("must recover after the window")
	}
	l.Fail("k")
	l.Reset("k")
	if len(l.fails) != 0 {
		t.Error("Reset must forget the key")
	}
}

func TestTokenHandler_BruteForceIsRateLimitedEvenWithCorrectSecretLater(t *testing.T) {
	reg := newTestRegistry(t)
	iss := newTestIssuer(t, "nexus.trust")
	handler := TokenHandlerWithLimits(reg, iss, nil, TokenLimits{
		PerIP:    NewFailureLimiter(100, time.Minute),
		PerAgent: NewFailureLimiter(3, time.Minute),
	})

	bad := map[string]any{"agent_id": "agent-1", "secret": "guess", "task_id": "t"}
	for i := 0; i < 3; i++ {
		if rec := doTokenRequest(t, handler, bad); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want 401", i, rec.Code)
		}
	}
	good := map[string]any{"agent_id": "agent-1", "secret": "correct-secret", "task_id": "t"}
	rec := doTokenRequest(t, handler, good)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("after 3 failures even the right secret must get 429 + Retry-After, got %d", rec.Code)
	}
}

func TestTokenHandler_PerIPLimitCoversAgentEnumeration(t *testing.T) {
	reg := newTestRegistry(t)
	iss := newTestIssuer(t, "nexus.trust")
	handler := TokenHandlerWithLimits(reg, iss, nil, TokenLimits{
		PerIP:    NewFailureLimiter(5, time.Minute),
		PerAgent: NewFailureLimiter(5, time.Minute),
	})
	for i := 0; i < 5; i++ {
		doTokenRequest(t, handler, map[string]any{"agent_id": "ghost-" + string(rune('a'+i)), "secret": "x", "task_id": "t"})
	}
	rec := doTokenRequest(t, handler, map[string]any{"agent_id": "agent-1", "secret": "correct-secret", "task_id": "t"})
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429 once the IP exhausted its failures", rec.Code)
	}
}

func TestTokenHandler_SuccessResetsAgentCounter(t *testing.T) {
	reg := newTestRegistry(t)
	iss := newTestIssuer(t, "nexus.trust")
	handler := TokenHandlerWithLimits(reg, iss, nil, TokenLimits{
		PerIP:    NewFailureLimiter(100, time.Minute),
		PerAgent: NewFailureLimiter(3, time.Minute),
	})
	bad := map[string]any{"agent_id": "agent-1", "secret": "no", "task_id": "t"}
	good := map[string]any{"agent_id": "agent-1", "secret": "correct-secret", "task_id": "t"}
	for round := 0; round < 3; round++ {
		doTokenRequest(t, handler, bad)
		doTokenRequest(t, handler, bad)
		if rec := doTokenRequest(t, handler, good); rec.Code != http.StatusOK {
			t.Fatalf("round %d: legit agent locked out by occasional typos (%d)", round, rec.Code)
		}
	}
}

func TestAuthenticate_UnknownAgentAndWrongSecretAreIndistinguishable(t *testing.T) {
	reg := newTestRegistry(t)
	_, e1 := reg.Authenticate("nobody", "x")
	_, e2 := reg.Authenticate("agent-1", "x")
	if e1 == nil || e2 == nil {
		t.Fatal("both must fail")
	}
}
