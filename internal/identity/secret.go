// secret.go hashes and verifies agents' bootstrap secrets.
//
// Format: "pbkdf2-sha256$<iterations>$<salt>$<hash>" (salt and hash are
// base64url, no padding). PBKDF2-HMAC-SHA256 is used because it can be
// built from the standard library alone (the project has no external
// dependencies); a random 16-byte salt per secret defeats precomputed
// tables, and the iteration count makes each guess expensive for an
// attacker who steals agents.json.
//
// The older format — a bare hex sha256("<agent_id>:<secret>") — is still
// accepted so existing registries keep working, but it is fast to brute
// force; LoadRegistry logs a warning for every such entry.
package identity

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	secretHashPrefix = "pbkdf2-sha256$"
	saltBytes        = 16
	hashBytes        = 32
	// maxHashIterations bounds the cost a (possibly attacker-edited)
	// stored hash can impose on an authentication attempt.
	maxHashIterations = 10_000_000
)

// hashIterations is the cost used for new hashes. A variable so tests
// can lower it; 600k follows OWASP's guidance for PBKDF2-HMAC-SHA256.
var hashIterations = 600_000

func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	var out []byte
	for block := 1; len(out) < keyLen; block++ {
		prf.Reset()
		prf.Write(salt)
		var idx [4]byte
		binary.BigEndian.PutUint32(idx[:], uint32(block))
		prf.Write(idx[:])
		u := prf.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iter; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

// HashSecret returns the stored form of an agent's bootstrap secret,
// with a fresh random salt. The agent ID is mixed into the password so a
// hash can't be moved to another agent's entry.
func HashSecret(agentID, secret string) string {
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		panic("identity: crypto/rand failed: " + err.Error())
	}
	return encodeHash(hashIterations, salt, pbkdf2SHA256([]byte(agentID+":"+secret), salt, hashIterations, hashBytes))
}

func encodeHash(iter int, salt, sum []byte) string {
	return secretHashPrefix + strconv.Itoa(iter) + "$" +
		base64.RawURLEncoding.EncodeToString(salt) + "$" +
		base64.RawURLEncoding.EncodeToString(sum)
}

// legacyHashSecret is the pre-PBKDF2 format.
func legacyHashSecret(agentID, secret string) string {
	sum := sha256.Sum256([]byte(agentID + ":" + secret))
	return hex.EncodeToString(sum[:])
}

func isLegacyHash(stored string) bool { return !strings.HasPrefix(stored, secretHashPrefix) }

// verifySecret checks (agentID, secret) against a stored hash in constant
// time with respect to the secret.
func verifySecret(agentID, secret, stored string) bool {
	if isLegacyHash(stored) {
		return subtle.ConstantTimeCompare([]byte(legacyHashSecret(agentID, secret)), []byte(stored)) == 1
	}
	iter, salt, want, err := decodeHash(stored)
	if err != nil {
		return false
	}
	got := pbkdf2SHA256([]byte(agentID+":"+secret), salt, iter, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func decodeHash(stored string) (iter int, salt, sum []byte, err error) {
	parts := strings.Split(strings.TrimPrefix(stored, secretHashPrefix), "$")
	if len(parts) != 3 {
		return 0, nil, nil, errors.New("malformed secret hash")
	}
	iter, err = strconv.Atoi(parts[0])
	if err != nil || iter < 1 || iter > maxHashIterations {
		return 0, nil, nil, fmt.Errorf("invalid iteration count %q", parts[0])
	}
	if salt, err = base64.RawURLEncoding.DecodeString(parts[1]); err != nil || len(salt) == 0 {
		return 0, nil, nil, errors.New("invalid salt")
	}
	if sum, err = base64.RawURLEncoding.DecodeString(parts[2]); err != nil || len(sum) == 0 {
		return 0, nil, nil, errors.New("invalid hash")
	}
	return iter, salt, sum, nil
}

// dummyHash is verified against when the agent doesn't exist, so an
// unknown agent costs the same time as a wrong secret.
var dummyHash = HashSecret("nexus-dummy-agent", "nexus-dummy-secret")
