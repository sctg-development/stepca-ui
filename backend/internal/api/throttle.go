package api

import (
	"sync"
	"time"
)

// loginThrottle limits password guessing. Failures are counted per username
// (the client address behind a tunnel/proxy is not a reliable key): after
// maxFailures within window the account is locked for lockout, and a global
// ceiling bounds the total attempt rate whatever the usernames tried.
// Successful logins reset the counter. State is in memory (reset on restart).
type loginThrottle struct {
	mu          sync.Mutex
	failures    map[string][]time.Time
	lockedUntil map[string]time.Time
	global      []time.Time

	maxFailures int
	window      time.Duration
	lockout     time.Duration
	globalMax   int
	now         func() time.Time
}

func newLoginThrottle() *loginThrottle {
	return &loginThrottle{
		failures:    map[string][]time.Time{},
		lockedUntil: map[string]time.Time{},
		maxFailures: 5,
		window:      15 * time.Minute,
		lockout:     15 * time.Minute,
		globalMax:   30, // attempts per minute, all usernames together
		now:         time.Now,
	}
}

// allow reports whether a login attempt for username may be evaluated now,
// and records it against the global rate.
func (t *loginThrottle) allow(username string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()

	cutoff := now.Add(-time.Minute)
	kept := t.global[:0]
	for _, ts := range t.global {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	t.global = kept
	if len(t.global) >= t.globalMax {
		return false
	}
	t.global = append(t.global, now)

	if until, ok := t.lockedUntil[username]; ok {
		if now.Before(until) {
			return false
		}
		delete(t.lockedUntil, username)
		delete(t.failures, username)
	}
	return true
}

func (t *loginThrottle) fail(username string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	cutoff := now.Add(-t.window)
	var recent []time.Time
	for _, ts := range t.failures[username] {
		if ts.After(cutoff) {
			recent = append(recent, ts)
		}
	}
	recent = append(recent, now)
	t.failures[username] = recent
	if len(recent) >= t.maxFailures {
		t.lockedUntil[username] = now.Add(t.lockout)
	}
}

func (t *loginThrottle) success(username string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.failures, username)
	delete(t.lockedUntil, username)
}
