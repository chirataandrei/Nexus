// Package admin protects the operator endpoints (kill switch, token
// revocation, budget policy changes) with a shared admin token. Without
// it, anyone who can reach the gateway's port could suspend every agent
// or raise their own budget.
package admin

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
)

// HashToken returns the hex SHA-256 stored in the config. A plain hash
// (no salt, no stretching) is appropriate here only because the token is
// a long random value from GenerateToken, not a human-chosen password.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Require wraps next so it only runs for requests carrying
// "Authorization: Bearer <admin token>" whose SHA-256 equals tokenHash.
func Require(tokenHash string, next http.Handler) http.Handler {
	want := []byte(strings.ToLower(tokenHash))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := HashToken(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") ||
			subtle.ConstantTimeCompare([]byte(got), want) != 1 {
			slog.Warn("nexus.admin.denied", "event", "admin_denied", "path", r.URL.Path, "remote_addr", r.RemoteAddr)
			w.Header().Set("WWW-Authenticate", `Bearer realm="nexus-admin"`)
			http.Error(w, "admin token required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// GenerateToken returns a new random 256-bit admin token (hex).
func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
