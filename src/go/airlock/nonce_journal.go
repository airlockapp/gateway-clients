package airlock

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// NonceJournal records seen nonces to prevent replay attacks.
// Entries expire after a configurable TTL and are pruned periodically.
type NonceJournal struct {
	mu          sync.Mutex
	seen        map[string]time.Time
	ttl         time.Duration
	persistPath string
	lastPrune   time.Time
}

// NewNonceJournal creates a new nonce journal.
// ttl controls how long nonces are retained (default: 15 minutes).
// persistPath is an optional file path for persisting nonces across restarts.
func NewNonceJournal(ttl time.Duration, persistPath string) *NonceJournal {
	if ttl == 0 {
		ttl = 15 * time.Minute
	}
	j := &NonceJournal{
		seen:        make(map[string]time.Time),
		ttl:         ttl,
		persistPath: persistPath,
		lastPrune:   time.Now(),
	}
	if persistPath != "" {
		j.loadFromFile()
	}
	return j
}

// TryRecord checks and records a nonce. Returns true if this is a new (unseen) nonce.
// Returns false if the nonce was already seen (replay detected).
func (j *NonceJournal) TryRecord(nonce string) bool {
	j.mu.Lock()
	defer j.mu.Unlock()

	j.maybePrune()

	now := time.Now()
	if ts, ok := j.seen[nonce]; ok && now.Sub(ts) < j.ttl {
		return false // replay
	}

	j.seen[nonce] = now
	j.maybePersist()
	return true
}

// HasSeen checks whether a nonce has already been seen (without recording it).
func (j *NonceJournal) HasSeen(nonce string) bool {
	j.mu.Lock()
	defer j.mu.Unlock()

	ts, ok := j.seen[nonce]
	return ok && time.Since(ts) < j.ttl
}

// Count returns the number of active (non-expired) nonces.
func (j *NonceJournal) Count() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.maybePrune()
	return len(j.seen)
}

func (j *NonceJournal) maybePrune() {
	if time.Since(j.lastPrune) < time.Minute {
		return
	}
	j.lastPrune = time.Now()
	cutoff := time.Now().Add(-j.ttl)
	for k, ts := range j.seen {
		if ts.Before(cutoff) {
			delete(j.seen, k)
		}
	}
}

func (j *NonceJournal) maybePersist() {
	if j.persistPath == "" {
		return
	}
	f, err := os.Create(j.persistPath)
	if err != nil {
		return // best-effort
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for k, ts := range j.seen {
		fmt.Fprintf(w, "%s\t%s\n", k, ts.Format(time.RFC3339Nano))
	}
	w.Flush()
}

func (j *NonceJournal) loadFromFile() {
	f, err := os.Open(j.persistPath)
	if err != nil {
		return // best-effort
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), "\t", 2)
		if len(parts) == 2 {
			if ts, err := time.Parse(time.RFC3339Nano, parts[1]); err == nil {
				j.seen[parts[0]] = ts
			}
		}
	}
}
