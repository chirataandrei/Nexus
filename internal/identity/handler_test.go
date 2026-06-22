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
	hash := HashSecret("agent-1", "secret-corect")
	content := `{
		"default_max_ttl_seconds": 300,
		"agents": [
			{"agent_id": "agent-1", "secret_hash": "` + hash + `", "allowed_scopes": ["llm:openai:invoke", "tools:internal:invoke"]}
		]
	}`
	dir := t.TempDir()
	path := filepath.Join(dir, "agents.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("nu pot scrie fișierul temporar: %v", err)
	}
	reg, err := LoadRegistry(path, 5*time.Minute)
	if err != nil {
		t.Fatalf("LoadRegistry a eșuat: %v", err)
	}
	return reg
}

func doTokenRequest(t *testing.T, handler http.HandlerFunc, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("nu pot serializa cererea: %v", err)
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
		"secret":   "secret-corect",
		"task_id":  "task-1",
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, vroiam 200, body=%s", rec.Code, rec.Body.String())
	}
	var resp TokenResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("răspuns JSON invalid: %v", err)
	}
	if resp.Token == "" {
		t.Error("token-ul emis ar trebui nevid")
	}

	// Tokenul emis trebuie să fie verificabil cu cheia publică a aceluiași issuer.
	if _, err := Verify(iss.PublicKey(), resp.Token); err != nil {
		t.Errorf("tokenul emis de handler nu trece verificarea: %v", err)
	}
}

func TestTokenHandler_RejectsWrongSecret(t *testing.T) {
	reg := newTestRegistry(t)
	iss := newTestIssuer(t, "nexus.trust")
	handler := TokenHandler(reg, iss, nil)

	rec := doTokenRequest(t, handler, map[string]any{
		"agent_id": "agent-1",
		"secret":   "secret-gresit",
		"task_id":  "task-1",
	})

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, vroiam 401", rec.Code)
	}
}

func TestTokenHandler_RejectsScopeEscalation(t *testing.T) {
	reg := newTestRegistry(t)
	iss := newTestIssuer(t, "nexus.trust")
	handler := TokenHandler(reg, iss, nil)

	rec := doTokenRequest(t, handler, map[string]any{
		"agent_id": "agent-1",
		"secret":   "secret-corect",
		"task_id":  "task-1",
		"scopes":   []string{"llm:openai:invoke", "admin:delete-everything"},
	})

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, vroiam 403 (escaladare de privilegii respinsă), body=%s", rec.Code, rec.Body.String())
	}
}

func TestTokenHandler_RejectsMissingFields(t *testing.T) {
	reg := newTestRegistry(t)
	iss := newTestIssuer(t, "nexus.trust")
	handler := TokenHandler(reg, iss, nil)

	rec := doTokenRequest(t, handler, map[string]any{"agent_id": "agent-1"})

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, vroiam 400", rec.Code)
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
		t.Errorf("status = %d, vroiam 405", rec.Code)
	}
}

func TestTokenHandler_RejectsSuspendedAgent(t *testing.T) {
	reg := newTestRegistry(t)
	iss := newTestIssuer(t, "nexus.trust")
	suspension := fakeSuspensionChecker{suspendedAgents: map[string]string{"agent-1": "comportament anormal"}}
	handler := TokenHandler(reg, iss, suspension)

	rec := doTokenRequest(t, handler, map[string]any{
		"agent_id": "agent-1",
		"secret":   "secret-corect",
		"task_id":  "task-1",
	})

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, vroiam 403 pentru un agent suspendat", rec.Code)
	}
}
