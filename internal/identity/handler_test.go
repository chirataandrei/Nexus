package identity

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestRegistry(t *testing.T) *Registry {
	t.Helper()
	hash := HashSecret("agent-1", "correct-secret")
	content := `{
		"default_max_ttl_seconds": 300,
		"agents": [
			{"agent_id": "agent-1", "secret_hash": "` + hash + `", "allowed_scopes": ["llm:openai:invoke", "tools:internal:invoke"]}
		]
	}`
	dir := t.TempDir()
	path := filepath.Join(dir, "agents.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("cannot write temp file: %v", err)
	}
	reg, err := LoadRegistry(path, 5*time.Minute)
	if err != nil {
		t.Fatalf("LoadRegistry failed: %v", err)
	}
	return reg
}

func doTokenRequest(t *testing.T, handler http.HandlerFunc, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("cannot serialize request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/nexus/identity/token", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

func TestTokenHandler_IssuesTokenForValidCredentials(t *testing.T) {
	reg := newTestRegistry(t)
	iss := newTestIssuer(t, "nexus.trust")
	handler := TokenHandler(reg, iss, nil)

	rec := doTokenRequest(t, handler, map[string]any{
		"agent_id": "agent-1",
		"secret":   "correct-secret",
		"task_id":  "task-1",
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var resp TokenResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if resp.Token == "" {
		t.Error("the issued token should be non-empty")
	}

	// The issued token must be verifiable with the same issuer's public key.
	if _, err := Verify(iss.PublicKey(), resp.Token); err != nil {
		t.Errorf("the token issued by the handler doesn't pass verification: %v", err)
	}
}

func TestTokenHandler_RejectsWrongSecret(t *testing.T) {
	reg := newTestRegistry(t)
	iss := newTestIssuer(t, "nexus.trust")
	handler := TokenHandler(reg, iss, nil)

	rec := doTokenRequest(t, handler, map[string]any{
		"agent_id": "agent-1",
		"secret":   "wrong-secret",
		"task_id":  "task-1",
	})

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestTokenHandler_RejectsScopeEscalation(t *testing.T) {
	reg := newTestRegistry(t)
	iss := newTestIssuer(t, "nexus.trust")
	handler := TokenHandler(reg, iss, nil)

	rec := doTokenRequest(t, handler, map[string]any{
		"agent_id": "agent-1",
		"secret":   "correct-secret",
		"task_id":  "task-1",
		"scopes":   []string{"llm:openai:invoke", "admin:delete-everything"},
	})

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (privilege escalation rejected), body=%s", rec.Code, rec.Body.String())
	}
}

func TestTokenHandler_RejectsMissingFields(t *testing.T) {
	reg := newTestRegistry(t)
	iss := newTestIssuer(t, "nexus.trust")
	handler := TokenHandler(reg, iss, nil)

	rec := doTokenRequest(t, handler, map[string]any{"agent_id": "agent-1"})

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestTokenHandler_RejectsNonPOST(t *testing.T) {
	reg := newTestRegistry(t)
	iss := newTestIssuer(t, "nexus.trust")
	handler := TokenHandler(reg, iss, nil)

	req := httptest.NewRequest(http.MethodGet, "/nexus/identity/token", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
}

func TestTokenHandler_RejectsSuspendedAgent(t *testing.T) {
	reg := newTestRegistry(t)
	iss := newTestIssuer(t, "nexus.trust")
	suspension := fakeSuspensionChecker{suspendedAgents: map[string]string{"agent-1": "abnormal behavior"}}
	handler := TokenHandler(reg, iss, suspension)

	rec := doTokenRequest(t, handler, map[string]any{
		"agent_id": "agent-1",
		"secret":   "correct-secret",
		"task_id":  "task-1",
	})

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for a suspended agent", rec.Code)
	}
}
