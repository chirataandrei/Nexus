package identity

import (
	"sync"
	"time"
)

// RevocationList holds the jti of tokens an operator has revoked before
// they expired. Entries are kept for MaxTokenTTLCeiling, after which the
// token is expired anyway, so the list stays small.
//
// It is in-memory: a restart empties it. That matches the gateway's
// other runtime state, and is bounded by the token TTL (minutes) — see
// docs/THREAT_MODEL.md.
type RevocationList struct {
	mu      sync.RWMutex
	revoked map[string]time.Time // jti -> forget-after
	now     func() time.Time
}

func NewRevocationList() *RevocationList {
	return &RevocationList{revoked: make(map[string]time.Time), now: time.Now}
}

// Revoke blocks the token with this jti from now on.
func (l *RevocationList) Revoke(jti string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for k, until := range l.revoked { // drop entries whose tokens have expired
		if now.After(until) {
			delete(l.revoked, k)
		}
	}
	l.revoked[jti] = now.Add(time.Duration(MaxTokenTTLCeiling) * time.Second)
}

// IsRevoked reports whether the jti has been revoked.
func (l *RevocationList) IsRevoked(jti string) bool {
	if jti == "" {
		return false
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	until, ok := l.revoked[jti]
	return ok && !l.now().After(until)
}
