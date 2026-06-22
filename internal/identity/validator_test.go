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
		t.Fatalf("NewIssuer failed: %v", err)
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
		t.Fatalf("IssueSVID failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/openai/models", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	meta := metaFor(req, "llm:openai:invoke")

	if err := v.Validate(context.Background(), meta, req); err != nil {
		t.Fatalf("Validate should accept a valid token with the correct scope: %v", err)
	}
	if meta.VerifiedAgentID != "agent-1" {
		t.Errorf("VerifiedAgentID should be populated, got %q", meta.VerifiedAgentID)
	}
	if meta.SPIFFEID == "" {
		t.Error("SPIFFEID should be populated after successful validation")
	}
}

func TestSPIFFEValidator_RejectsMissingAuthorizationHeader(t *testing.T) {
	iss := newTestIssuer(t, "nexus.trust")
	v := NewSPIFFEValidator(iss.PublicKey(), "nexus.trust", nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/openai/models", nil)
	meta := metaFor(req, "")

	if err := v.Validate(context.Background(), meta, req); err == nil {
		t.Error("Validate should reject a request without an Authorization header")
	}
}

func TestSPIFFEValidator_RejectsInsufficientScope(t *testing.T) {
	iss := newTestIssuer(t, "nexus.trust")
	v := NewSPIFFEValidator(iss.PublicKey(), "nexus.trust", nil)

	token, _, err := iss.IssueSVID("agent-1", "task-1", []string{"tools:internal:invoke"}, time.Minute)
	if err != nil {
		t.Fatalf("IssueSVID failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/openai/models", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	meta := metaFor(req, "llm:openai:invoke") // the route requires a different scope than the token has

	if err := v.Validate(context.Background(), meta, req); err == nil {
		t.Error("Validate should reject a token without the scope the route requires")
	}
}

func TestSPIFFEValidator_RejectsWrongTrustDomain(t *testing.T) {
	iss := newTestIssuer(t, "other-domain.trust")
	// The gateway's validator only accepts "nexus.trust".
	v := NewSPIFFEValidator(iss.PublicKey(), "nexus.trust", nil)

	token, _, err := iss.IssueSVID("agent-1", "task-1", []string{"llm:openai:invoke"}, time.Minute)
	if err != nil {
		t.Fatalf("IssueSVID failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/openai/models", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	meta := metaFor(req, "")

	if err := v.Validate(context.Background(), meta, req); err == nil {
		t.Error("Validate should reject a token issued for a different trust domain")
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
	suspension := fakeSuspensionChecker{suspendedAgents: map[string]string{"agent-1": "abnormal behavior"}}
	v := NewSPIFFEValidator(iss.PublicKey(), "nexus.trust", suspension)

	token, _, err := iss.IssueSVID("agent-1", "task-1", []string{"llm:openai:invoke"}, time.Minute)
	if err != nil {
		t.Fatalf("IssueSVID failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/openai/models", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	meta := metaFor(req, "")

	if err := v.Validate(context.Background(), meta, req); err == nil {
		t.Error("Validate should reject a suspended agent, even with an otherwise valid token")
	}
}

func TestSPIFFEValidator_AllowsNonSuspendedAgentWithSuspensionCheckerConfigured(t *testing.T) {
	iss := newTestIssuer(t, "nexus.trust")
	suspension := fakeSuspensionChecker{suspendedAgents: map[string]string{"other-agent": "reason"}}
	v := NewSPIFFEValidator(iss.PublicKey(), "nexus.trust", suspension)

	token, _, err := iss.IssueSVID("agent-1", "task-1", []string{"llm:openai:invoke"}, time.Minute)
	if err != nil {
		t.Fatalf("IssueSVID failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/openai/models", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	meta := metaFor(req, "llm:openai:invoke")

	if err := v.Validate(context.Background(), meta, req); err != nil {
		t.Errorf("a non-suspended agent shouldn't be affected by another agent's suspension: %v", err)
	}
}

func TestSPIFFEValidator_RejectsExpiredToken(t *testing.T) {
	iss := newTestIssuer(t, "nexus.trust")
	v := NewSPIFFEValidator(iss.PublicKey(), "nexus.trust", nil)

	token, _, err := iss.IssueSVID("agent-1", "task-1", nil, time.Nanosecond)
	if err != nil {
		t.Fatalf("IssueSVID failed: %v", err)
	}
	time.Sleep(10 * time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "/v1/openai/models", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	meta := metaFor(req, "")

	if err := v.Validate(context.Background(), meta, req); err == nil {
		t.Error("Validate should reject an expired token (extremely short TTL, already passed)")
	}
}
