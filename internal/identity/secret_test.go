package identity

import "testing"

func init() { hashIterations = 1000 } // keep the suite fast

func TestSecretHash_PBKDF2RoundTrip(t *testing.T) {
	h := HashSecret("agent-1", "s3cret")
	if isLegacyHash(h) {
		t.Fatalf("new hashes must use the PBKDF2 format, got %q", h)
	}
	if !verifySecret("agent-1", "s3cret", h) {
		t.Error("correct secret rejected")
	}
	if verifySecret("agent-1", "wrong", h) || verifySecret("agent-2", "s3cret", h) {
		t.Error("wrong secret or other agent accepted")
	}
	if HashSecret("agent-1", "s3cret") == h {
		t.Error("two hashes of the same secret must differ (random salt)")
	}
}

func TestSecretHash_LegacyStillVerifies(t *testing.T) {
	h := legacyHashSecret("agent-1", "old")
	if !isLegacyHash(h) || !verifySecret("agent-1", "old", h) || verifySecret("agent-1", "x", h) {
		t.Error("legacy sha256 hashes must keep verifying")
	}
}

func TestSecretHash_MalformedNeverVerifies(t *testing.T) {
	for _, h := range []string{
		"pbkdf2-sha256$", "pbkdf2-sha256$abc$x$y", "pbkdf2-sha256$0$AA$AA",
		"pbkdf2-sha256$99999999999$AA$AA", "pbkdf2-sha256$1000$$", "pbkdf2-sha256$1000$AA",
	} {
		if verifySecret("a", "b", h) {
			t.Errorf("%q must not verify", h)
		}
	}
}

// RFC 7914 §11 PBKDF2-HMAC-SHA-256 test vector (c=1, dkLen=64 prefix).
func TestPBKDF2_KnownVector(t *testing.T) {
	got := pbkdf2SHA256([]byte("passwd"), []byte("salt"), 1, 32)
	want := "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
	if hexs := encodeHex(got); hexs != want {
		t.Errorf("PBKDF2 = %s, want %s", hexs, want)
	}
}

func encodeHex(b []byte) string {
	const d = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, x := range b {
		out = append(out, d[x>>4], d[x&15])
	}
	return string(out)
}
