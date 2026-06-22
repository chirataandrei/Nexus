package identity

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"nexus-gateway/internal/parser"
)

func newTestIssuer(t *testing.T, trustDomain string) *Issuer {
	t.Helper()
	iss, err := NewIssuer(trustDomain, 5*time.Minute)
	if err != nil {
		t.Fatalf("NewIssuer a eșuat: %v", err)
	}
	return iss
}

func metaFor(req *http.Request, requiredScope string) *parser.RequestMeta {
	meta, _, _ := parser.Parse(req)
	meta.RequiredScope = requiredScope
	return meta
}

func TestSPIFFEValidator_AcceptsValidToken(t *testing.T) {
	iss := newTestIssuer(t, "nexus.trust")
	v := NewSPIFFEValidator(iss.PublicKey(), "nexus.trust", nil)

	token, _, err := iss.IssueSVID("agent-1", "task-1", []string{"llm:openai:invoke"}, time.Minute)
	if err != nil {
		t.Fatalf("IssueSVID a eșuat: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/openai/models", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	meta := metaFor(req, "llm:openai:invoke")

	if err := v.Validate(context.Background(), meta, req); err != nil {
		t.Fatalf("Validate ar trebui să accepte un token valid cu scope corect: %v", err)
	}
	if meta.VerifiedAgentID != "agent-1" {
		t.Errorf("VerifiedAgentID ar trebui populat, am primit %q", meta.VerifiedAgentID)
	}
	if meta.SPIFFEID == "" {
		t.Error("SPIFFEID ar trebui populat după validare cu succes")
	}
}

func TestSPIFFEValidator_RejectsMissingAuthorizationHeader(t *testing.T) {
	iss := newTestIssuer(t, "nexus.trust")
	v := NewSPIFFEValidator(iss.PublicKey(), "nexus.trust", nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/openai/models", nil)
	meta := metaFor(req, "")

	if err := v.Validate(context.Background(), meta, req); err == nil {
		t.Error("Validate ar trebui să respingă o cerere fără antet Authorization")
	}
}

func TestSPIFFEValidator_RejectsInsufficientScope(t *testing.T) {
	iss := newTestIssuer(t, "nexus.trust")
	v := NewSPIFFEValidator(iss.PublicKey(), "nexus.trust", nil)

	token, _, err := iss.IssueSVID("agent-1", "task-1", []string{"tools:internal:invoke"}, time.Minute)
	if err != nil {
		t.Fatalf("IssueSVID a eșuat: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/openai/models", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	meta := metaFor(req, "llm:openai:invoke") // ruta cere alt scope decât are tokenul

	if err := v.Validate(context.Background(), meta, req); err == nil {
		t.Error("Validate ar trebui să respingă un token fără scope-ul cerut de rută")
	}
}

func TestSPIFFEValidator_RejectsWrongTrustDomain(t *testing.T) {
	iss := newTestIssuer(t, "alt-domeniu.trust")
	// Validatorul gateway-ului acceptă doar "nexus.trust".
	v := NewSPIFFEValidator(iss.PublicKey(), "nexus.trust", nil)

	token, _, err := iss.IssueSVID("agent-1", "task-1", []string{"llm:openai:invoke"}, time.Minute)
	if err != nil {
		t.Fatalf("IssueSVID a eșuat: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/openai/models", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	meta := metaFor(req, "")

	if err := v.Validate(context.Background(), meta, req); err == nil {
		t.Error("Validate ar trebui să respingă un token emis pentru alt domeniu de încredere")
	}
}

type fakeSuspensionChecker struct {
	suspendedAgents map[string]string
}

func (f fakeSuspensionChecker) IsSuspended(agentID string) (bool, string) {
	reason, ok := f.suspendedAgents[agentID]
	return ok, reason
}

func TestSPIFFEValidator_RejectsSuspendedAgent(t *testing.T) {
	iss := newTestIssuer(t, "nexus.trust")
	suspension := fakeSuspensionChecker{suspendedAgents: map[string]string{"agent-1": "comportament anormal"}}
	v := NewSPIFFEValidator(iss.PublicKey(), "nexus.trust", suspension)

	token, _, err := iss.IssueSVID("agent-1", "task-1", []string{"llm:openai:invoke"}, time.Minute)
	if err != nil {
		t.Fatalf("IssueSVID a eșuat: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/openai/models", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	meta := metaFor(req, "")

	if err := v.Validate(context.Background(), meta, req); err == nil {
		t.Error("Validate ar trebui să respingă un agent suspendat, chiar cu token altfel valid")
	}
}

func TestSPIFFEValidator_AllowsNonSuspendedAgentWithSuspensionCheckerConfigured(t *testing.T) {
	iss := newTestIssuer(t, "nexus.trust")
	suspension := fakeSuspensionChecker{suspendedAgents: map[string]string{"agent-altul": "motiv"}}
	v := NewSPIFFEValidator(iss.PublicKey(), "nexus.trust", suspension)

	token, _, err := iss.IssueSVID("agent-1", "task-1", []string{"llm:openai:invoke"}, time.Minute)
	if err != nil {
		t.Fatalf("IssueSVID a eșuat: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/openai/models", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	meta := metaFor(req, "llm:openai:invoke")

	if err := v.Validate(context.Background(), meta, req); err != nil {
		t.Errorf("un agent neasuspendat nu ar trebui afectat de suspendarea altui agent: %v", err)
	}
}

func TestSPIFFEValidator_RejectsExpiredToken(t *testing.T) {
	iss := newTestIssuer(t, "nexus.trust")
	v := NewSPIFFEValidator(iss.PublicKey(), "nexus.trust", nil)

	token, _, err := iss.IssueSVID("agent-1", "task-1", nil, time.Nanosecond)
	if err != nil {
		t.Fatalf("IssueSVID a eșuat: %v", err)
	}
	time.Sleep(10 * time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "/v1/openai/models", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	meta := metaFor(req, "")

	if err := v.Validate(context.Background(), meta, req); err == nil {
		t.Error("Validate ar trebui să respingă un token expirat (TTL extrem de scurt, deja trecut)")
	}
}
