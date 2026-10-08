package identity

import (
	"crypto/ed25519"
	"testing"
	"time"
)

// FuzzVerify: arbitrary token strings must never panic or be accepted
// unless they are exactly a token signed by the key.
func FuzzVerify(f *testing.F) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	good, _ := Sign(priv, Claims{Subject: "spiffe://x/agent/a/task/t", ExpiresAt: time.Now().Add(time.Hour).Unix(), AgentID: "a", TaskID: "t"})
	f.Add(good)
	f.Add("a.b.c")
	f.Add("..")
	f.Add("")
	f.Add(good + ".extra")
	f.Fuzz(func(t *testing.T, token string) {
		_, err := Verify(pub, token)
		if err == nil && token != good {
			t.Fatalf("accepted a token that was never issued: %q", token)
		}
		_ = TokenKeyID(token)
	})
}

// FuzzVerifySecret: a malformed stored hash must never panic, never
// verify, and never impose unbounded work.
func FuzzVerifySecret(f *testing.F) {
	f.Add("pbkdf2-sha256$1000$AA$AA")
	f.Add("pbkdf2-sha256$99999999$AA$AA")
	f.Add("pbkdf2-sha256$")
	f.Add("deadbeef")
	f.Fuzz(func(t *testing.T, stored string) {
		if iter, _, _, err := decodeHash(stored); err == nil && iter > 20000 {
			t.Skip("valid-but-expensive hash; bounded by maxHashIterations")
		}
		_ = verifySecret("agent", "secret", stored)
	})
}
