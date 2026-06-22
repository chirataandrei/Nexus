package identity

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTempAgentsFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "agents.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("cannot write temp file: %v", err)
	}
	return path
}

func TestLoadRegistry_ValidFile(t *testing.T) {
	hash := HashSecret("agent-1", "super-secret")
	content := `{
		"default_max_ttl_seconds": 120,
		"agents": [
			{"agent_id": "agent-1", "secret_hash": "` + hash + `", "allowed_scopes": ["scope:a", "scope:b"]}
		]
	}`
	path := writeTempAgentsFile(t, content)

	reg, err := LoadRegistry(path, 5*time.Minute)
	if err != nil {
		t.Fatalf("LoadRegistry failed: %v", err)
	}
	if reg.DefaultMaxTTL() != 120*time.Second {
		t.Errorf("default_max_ttl_seconds wasn't read correctly: %v", reg.DefaultMaxTTL())
	}

	rec, err := reg.Authenticate("agent-1", "super-secret")
	if err != nil {
		t.Fatalf("Authenticate should accept the correct secret: %v", err)
	}
	if len(rec.AllowedScopes) != 2 {
		t.Errorf("allowed_scopes read incorrectly: %v", rec.AllowedScopes)
	}
}

func TestLoadRegistry_RejectsDuplicateAgentID(t *testing.T) {
	hash := HashSecret("agent-1", "secret")
	content := `{"agents": [
		{"agent_id": "agent-1", "secret_hash": "` + hash + `", "allowed_scopes": []},
		{"agent_id": "agent-1", "secret_hash": "` + hash + `", "allowed_scopes": []}
	]}`
	path := writeTempAgentsFile(t, content)

	if _, err := LoadRegistry(path, time.Minute); err == nil {
		t.Error("LoadRegistry should reject a duplicate agent_id")
	}
}

func TestLoadRegistry_RejectsEmptyFile(t *testing.T) {
	path := writeTempAgentsFile(t, `{"agents": []}`)
	if _, err := LoadRegistry(path, time.Minute); err == nil {
		t.Error("LoadRegistry should reject a registry with no agents")
	}
}

func TestRegistry_Authenticate_WrongSecret(t *testing.T) {
	hash := HashSecret("agent-1", "the-correct-secret")
	content := `{"agents": [{"agent_id": "agent-1", "secret_hash": "` + hash + `", "allowed_scopes": []}]}`
	path := writeTempAgentsFile(t, content)
	reg, err := LoadRegistry(path, time.Minute)
	if err != nil {
		t.Fatalf("LoadRegistry failed: %v", err)
	}

	if _, err := reg.Authenticate("agent-1", "wrong-secret"); err == nil {
		t.Error("Authenticate should reject a wrong secret")
	}
}

func TestRegistry_Authenticate_UnknownAgent(t *testing.T) {
	hash := HashSecret("agent-1", "secret")
	content := `{"agents": [{"agent_id": "agent-1", "secret_hash": "` + hash + `", "allowed_scopes": []}]}`
	path := writeTempAgentsFile(t, content)
	reg, err := LoadRegistry(path, time.Minute)
	if err != nil {
		t.Fatalf("LoadRegistry failed: %v", err)
	}

	if _, err := reg.Authenticate("unknown-agent", "anything"); err == nil {
		t.Error("Authenticate should reject a nonexistent agent")
	}
}

func TestAgentRecord_EnsureScopesAllowed(t *testing.T) {
	rec := AgentRecord{AgentID: "agent-1", AllowedScopes: []string{"scope:a", "scope:b"}}

	if err := rec.EnsureScopesAllowed([]string{"scope:a"}); err != nil {
		t.Errorf("an allowed scope should be accepted: %v", err)
	}
	if err := rec.EnsureScopesAllowed([]string{"scope:a", "scope:b"}); err != nil {
		t.Errorf("all allowed scopes should be accepted: %v", err)
	}
	if err := rec.EnsureScopesAllowed([]string{"scope:c"}); err == nil {
		t.Error("a disallowed scope (privilege escalation) should be rejected")
	}
	if err := rec.EnsureScopesAllowed([]string{"scope:a", "scope:escalation"}); err == nil {
		t.Error("a mix of valid+disallowed scopes should be rejected entirely")
	}
}

func TestAgentRecord_MaxTTL(t *testing.T) {
	withOverride := AgentRecord{MaxTTLSeconds: 30}
	if got := withOverride.MaxTTL(5 * time.Minute); got != 30*time.Second {
		t.Errorf("MaxTTL should use the agent's override, got %v", got)
	}

	withoutOverride := AgentRecord{}
	if got := withoutOverride.MaxTTL(5 * time.Minute); got != 5*time.Minute {
		t.Errorf("MaxTTL should use the fallback, got %v", got)
	}
}
