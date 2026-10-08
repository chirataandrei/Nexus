package identity

import (
	"sync"
	"time"
)

// FailureLimiter blocks a key (e.g. a client IP) once it has produced
// max failures inside the sliding window. It only counts failures, so
// legitimate traffic that authenticates correctly is never slowed.
type FailureLimiter struct {
	mu      sync.Mutex
	max     int
	window  time.Duration
	maxKeys int
	fails   map[string][]time.Time
	now     func() time.Time
}

// NewFailureLimiter builds a limiter. max <= 0 disables it.
func NewFailureLimiter(max int, window time.Duration) *FailureLimiter {
	return &FailureLimiter{max: max, window: window, maxKeys: 10000, fails: make(map[string][]time.Time), now: time.Now}
}

func (l *FailureLimiter) recentLocked(key string, now time.Time) []time.Time {
	ts := l.fails[key]
	cut := 0
	for cut < len(ts) && now.Sub(ts[cut]) >= l.window {
		cut++
	}
	ts = ts[cut:]
	if len(ts) == 0 {
		delete(l.fails, key)
		return nil
	}
	l.fails[key] = ts
	return ts
}

// Blocked reports whether key is currently blocked and, if so, how long
// until its oldest counted failure leaves the window.
func (l *FailureLimiter) Blocked(key string) (bool, time.Duration) {
	if l == nil || l.max <= 0 {
		return false, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	ts := l.recentLocked(key, now)
	if len(ts) < l.max {
		return false, 0
	}
	return true, l.window - now.Sub(ts[len(ts)-l.max])
}

// Fail records a failed attempt for key.
func (l *FailureLimiter) Fail(key string) {
	if l == nil || l.max <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if _, ok := l.fails[key]; !ok && len(l.fails) >= l.maxKeys {
		for k := range l.fails { // bound memory: forget expired keys, then any one
			l.recentLocked(k, now)
		}
		for k := range l.fails {
			if len(l.fails) < l.maxKeys {
				break
			}
			delete(l.fails, k)
		}
	}
	l.fails[key] = append(l.fails[key], now)
}

// Reset forgets key's failures (after a successful authentication).
func (l *FailureLimiter) Reset(key string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	delete(l.fails, key)
	l.mu.Unlock()
}
