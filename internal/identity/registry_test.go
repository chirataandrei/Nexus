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
		t.Fatalf("nu pot scrie fișierul temporar: %v", err)
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
		t.Fatalf("LoadRegistry a eșuat: %v", err)
	}
	if reg.DefaultMaxTTL() != 120*time.Second {
		t.Errorf("default_max_ttl_seconds nu a fost citit corect: %v", reg.DefaultMaxTTL())
	}

	rec, err := reg.Authenticate("agent-1", "super-secret")
	if err != nil {
		t.Fatalf("Authenticate ar trebui să accepte secretul corect: %v", err)
	}
	if len(rec.AllowedScopes) != 2 {
		t.Errorf("allowed_scopes citite greșit: %v", rec.AllowedScopes)
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
		t.Error("LoadRegistry ar trebui să respingă agent_id duplicat")
	}
}

func TestLoadRegistry_RejectsEmptyFile(t *testing.T) {
	path := writeTempAgentsFile(t, `{"agents": []}`)
	if _, err := LoadRegistry(path, time.Minute); err == nil {
		t.Error("LoadRegistry ar trebui să respingă un registru fără agenți")
	}
}

func TestRegistry_Authenticate_WrongSecret(t *testing.T) {
	hash := HashSecret("agent-1", "secretul-corect")
	content := `{"agents": [{"agent_id": "agent-1", "secret_hash": "` + hash + `", "allowed_scopes": []}]}`
	path := writeTempAgentsFile(t, content)
	reg, err := LoadRegistry(path, time.Minute)
	if err != nil {
		t.Fatalf("LoadRegistry a eșuat: %v", err)
	}

	if _, err := reg.Authenticate("agent-1", "secret-gresit"); err == nil {
		t.Error("Authenticate ar trebui să respingă un secret greșit")
	}
}

func TestRegistry_Authenticate_UnknownAgent(t *testing.T) {
	hash := HashSecret("agent-1", "secret")
	content := `{"agents": [{"agent_id": "agent-1", "secret_hash": "` + hash + `", "allowed_scopes": []}]}`
	path := writeTempAgentsFile(t, content)
	reg, err := LoadRegistry(path, time.Minute)
	if err != nil {
		t.Fatalf("LoadRegistry a eșuat: %v", err)
	}

	if _, err := reg.Authenticate("agent-necunoscut", "orice"); err == nil {
		t.Error("Authenticate ar trebui să respingă un agent inexistent")
	}
}

func TestAgentRecord_EnsureScopesAllowed(t *testing.T) {
	rec := AgentRecord{AgentID: "agent-1", AllowedScopes: []string{"scope:a", "scope:b"}}

	if err := rec.EnsureScopesAllowed([]string{"scope:a"}); err != nil {
		t.Errorf("scope permis ar trebui acceptat: %v", err)
	}
	if err := rec.EnsureScopesAllowed([]string{"scope:a", "scope:b"}); err != nil {
		t.Errorf("toate scope-urile permise ar trebui acceptate: %v", err)
	}
	if err := rec.EnsureScopesAllowed([]string{"scope:c"}); err == nil {
		t.Error("un scope nepermis (escaladare de privilegii) ar trebui respins")
	}
	if err := rec.EnsureScopesAllowed([]string{"scope:a", "scope:escaladare"}); err == nil {
		t.Error("un mix valid+nepermis ar trebui respins în întregime")
	}
}

func TestAgentRecord_MaxTTL(t *testing.T) {
	withOverride := AgentRecord{MaxTTLSeconds: 30}
	if got := withOverride.MaxTTL(5 * time.Minute); got != 30*time.Second {
		t.Errorf("MaxTTL ar trebui să folosească override-ul agentului, am primit %v", got)
	}

	withoutOverride := AgentRecord{}
	if got := withoutOverride.MaxTTL(5 * time.Minute); got != 5*time.Minute {
		t.Errorf("MaxTTL ar trebui să folosească fallback-ul, am primit %v", got)
	}
}
