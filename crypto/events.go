package crypto

import (
	"crypto/tls"
	"sync"
)

const defaultEventLimit = 100

// EventStore retains a bounded in-memory list of recent security events.
type EventStore struct {
	mu     sync.RWMutex
	events []SecurityEvent
	limit  int
}

// NewEventStore creates an event store with the given capacity limit.
func NewEventStore(limit int) *EventStore {
	if limit <= 0 {
		limit = defaultEventLimit
	}
	return &EventStore{
		events: make([]SecurityEvent, 0, limit),
		limit:  limit,
	}
}

// Add appends an event, dropping the oldest when the limit is exceeded.
func (s *EventStore) Add(ev SecurityEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.events) >= s.limit {
		copy(s.events, s.events[1:])
		s.events[len(s.events)-1] = ev
		return
	}
	s.events = append(s.events, ev)
}

// Snapshot returns a copy of recent events (oldest first).
func (s *EventStore) Snapshot() []SecurityEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]SecurityEvent, len(s.events))
	copy(out, s.events)
	return out
}

// Len returns the number of stored events.
func (s *EventStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.events)
}

// PrimaryConfiguredGroup returns the first configured curve, or 0 if empty.
func PrimaryConfiguredGroup(provider CryptoProvider) tls.CurveID {
	curves := provider.CurvePreferences()
	if len(curves) == 0 {
		return 0
	}
	return curves[0]
}
