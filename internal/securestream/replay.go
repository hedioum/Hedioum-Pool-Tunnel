package securestream

import (
	"sync"
	"time"
)

// replayTTL is how long an accepted salt is remembered, measured on the egress's
// OWN monotonic clock. It intentionally does not depend on the client's clock or
// any external time source, so the two nodes need no clock synchronization.
const replayTTL = 24 * time.Hour

// ReplayFilter remembers recently-accepted client salts so a captured handshake
// cannot be replayed. Entries expire after replayTTL (server-local), and the
// total size is bounded to stay memory-safe under flooding.
type ReplayFilter struct {
	mu      sync.Mutex
	seen    map[string]time.Time // salt -> expiry (server-local)
	maxSize int
}

// NewReplayFilter returns a filter bounded to roughly maxSize live entries.
func NewReplayFilter(maxSize int) *ReplayFilter {
	if maxSize <= 0 {
		maxSize = 50000
	}
	return &ReplayFilter{
		seen:    make(map[string]time.Time),
		maxSize: maxSize,
	}
}

// Accept records salt as used and reports whether it was previously unseen. A
// replayed salt returns false.
func (f *ReplayFilter) Accept(salt []byte) bool {
	key := saltKey(salt)

	f.mu.Lock()
	defer f.mu.Unlock()

	if _, exists := f.seen[key]; exists {
		return false
	}

	now := time.Now()
	if len(f.seen) >= f.maxSize {
		f.evict(now)
	}
	f.seen[key] = now.Add(replayTTL)
	return true
}

// evict drops expired entries; if that is not enough, it clears the map wholesale
// to enforce the hard size bound (fail-safe against flooding, at the cost of a
// brief replay window for very old salts that are outside the auth window anyway).
func (f *ReplayFilter) evict(now time.Time) {
	for k, exp := range f.seen {
		if now.After(exp) {
			delete(f.seen, k)
		}
	}
	if len(f.seen) >= f.maxSize {
		f.seen = make(map[string]time.Time)
	}
}

// saltKey turns the raw salt bytes into a map key. Salts are already
// high-entropy, so the raw bytes serve directly as the key.
func saltKey(salt []byte) string {
	return string(salt)
}
