package keystore

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreate_PersistsAcrossRestarts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "k.json")
	k1, created, err := LoadOrCreate(path)
	if err != nil || !created {
		t.Fatalf("first call: created=%v err=%v", created, err)
	}
	k2, created, err := LoadOrCreate(path)
	if err != nil || created {
		t.Fatalf("second call: created=%v err=%v", created, err)
	}
	if string(k1) != string(k2) {
		t.Error("the key changed between loads")
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("key file mode = %v, want 0600", fi.Mode().Perm())
	}
}

func TestLoadOrCreate_RejectsEditedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k.json")
	if _, _, err := LoadOrCreate(path); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	var f keyFile
	_ = json.Unmarshal(raw, &f)
	f.KID = "deadbeefdeadbeef"
	edited, _ := json.Marshal(f)
	_ = os.WriteFile(path, edited, 0o600)
	if _, _, err := LoadOrCreate(path); err == nil {
		t.Error("a key file with a mismatched kid must be rejected")
	}
}

func TestPublicKeySet_RoundTrip(t *testing.T) {
	priv, _, _ := LoadOrCreate(filepath.Join(t.TempDir(), "k.json"))
	pub := priv.Public().(ed25519.PublicKey)

	p := filepath.Join(t.TempDir(), "retired.json")
	body := `{"` + KeyID(pub) + `":"` + EncodePublic(pub) + `"}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := LoadPublicKeys(p)
	if err != nil || !set[KeyID(pub)].Equal(pub) {
		t.Fatalf("LoadPublicKeys: %v %v", set, err)
	}

	bad := `{"0000000000000000":"` + EncodePublic(pub) + `"}`
	_ = os.WriteFile(p, []byte(bad), 0o600)
	if _, err := LoadPublicKeys(p); err == nil {
		t.Error("a kid that doesn't match its key must be rejected")
	}
}
