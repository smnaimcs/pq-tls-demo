package main

import (
	"crypto/tls"
	"encoding/json"
	"log"
	"net/http"
	"sync"

	democrypto "pq-tls-demo/crypto"
)

// postureStore tracks provider, policy, latest TLS state, latest evaluation,
// and recent security events for /cbom, /status, and /security-events.
type postureStore struct {
	mu         sync.RWMutex
	provider   democrypto.CryptoProvider
	policy     democrypto.CryptoPolicyMode
	lastTLS    *tls.ConnectionState
	lastResult *democrypto.PolicyResult
	events     *democrypto.EventStore
}

func newPostureStore(provider democrypto.CryptoProvider, policy democrypto.CryptoPolicyMode) *postureStore {
	return &postureStore{
		provider: provider,
		policy:   policy,
		events:   democrypto.NewEventStore(100),
	}
}

// observe records TLS state, evaluates policy, stores a security event, and logs it.
func (s *postureStore) observe(state *tls.ConnectionState) democrypto.PolicyResult {
	if state == nil {
		return democrypto.PolicyResult{}
	}
	cp := *state
	result := democrypto.EvaluatePolicy(s.policy, s.provider.CurvePreferences(), cp.CurveID)
	ev := democrypto.NewSecurityEvent(s.provider.ID(), result)

	s.mu.Lock()
	s.lastTLS = &cp
	s.lastResult = &result
	s.mu.Unlock()

	s.events.Add(ev)

	log.Printf("%s policy=%s negotiated=%s severity=%s",
		ev.Type, ev.Policy, ev.NegotiatedGroup, ev.Severity)

	return result
}

func (s *postureStore) inventory() democrypto.CryptoInventory {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return democrypto.BuildInventory(s.provider, s.lastTLS)
}

type statusResponse struct {
	Provider            string  `json:"provider"`
	Policy              string  `json:"policy"`
	LastNegotiatedGroup *string `json:"last_negotiated_group"`
	PolicyStatus        string  `json:"policy_status"`
}

func (s *postureStore) status() statusResponse {
	s.mu.RLock()
	defer s.mu.RUnlock()

	resp := statusResponse{
		Provider:     s.provider.ID(),
		Policy:       string(s.policy),
		PolicyStatus: "no_connection",
	}
	if s.lastTLS != nil {
		g := s.lastTLS.CurveID.String()
		resp.LastNegotiatedGroup = &g
	}
	if s.lastResult != nil {
		resp.PolicyStatus = s.lastResult.Status
	}
	return resp
}

func (s *postureStore) handleCBOM(w http.ResponseWriter, r *http.Request) {
	if r.TLS != nil {
		s.observe(r.TLS)
	}
	writeJSON(w, s.inventory())
}

func (s *postureStore) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.TLS != nil {
		s.observe(r.TLS)
	}
	writeJSON(w, s.status())
}

func (s *postureStore) handleSecurityEvents(w http.ResponseWriter, r *http.Request) {
	if r.TLS != nil {
		s.observe(r.TLS)
	}
	writeJSON(w, map[string]any{
		"events": s.events.Snapshot(),
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		http.Error(w, "failed to encode JSON", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
	_, _ = w.Write([]byte("\n"))
}
