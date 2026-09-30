package crypto

import (
	"crypto/tls"
	"testing"
)

// TestPolicyMatrix covers the full deterministic policy evaluation matrix.
func TestPolicyMatrix(t *testing.T) {
	hybridCfg := []tls.CurveID{tls.X25519MLKEM768}
	classicalCfg := []tls.CurveID{tls.X25519}

	cases := []struct {
		name       string
		mode       CryptoPolicyMode
		configured []tls.CurveID
		negotiated tls.CurveID
		status     string
		compliant  bool
		eventType  string
		severity   string
	}{
		{"HYBRID_REQUIRED + X25519MLKEM768", HybridRequired, hybridCfg, tls.X25519MLKEM768, StatusCompliant, true, EventCompliant, SeverityCompliant},
		{"HYBRID_REQUIRED + X25519", HybridRequired, hybridCfg, tls.X25519, StatusViolation, false, EventViolation, SeverityAlert},
		{"HYBRID_PREFERRED + X25519MLKEM768", HybridPreferred, hybridCfg, tls.X25519MLKEM768, StatusCompliant, true, EventCompliant, SeverityCompliant},
		{"HYBRID_PREFERRED + X25519", HybridPreferred, hybridCfg, tls.X25519, StatusFallback, true, EventFallback, SeverityWarning},
		{"LEGACY_ALLOWED + X25519MLKEM768", LegacyAllowed, classicalCfg, tls.X25519MLKEM768, StatusCompliant, true, EventCompliant, SeverityCompliant},
		{"LEGACY_ALLOWED + X25519", LegacyAllowed, classicalCfg, tls.X25519, StatusCompliant, true, EventCompliant, SeverityCompliant},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := EvaluatePolicy(tc.mode, tc.configured, tc.negotiated)
			assertPolicy(t, r, tc.status, tc.compliant, tc.eventType, tc.severity)
		})
	}
}

func TestHybridRequiredWithHybrid(t *testing.T) {
	r := EvaluatePolicy(HybridRequired, []tls.CurveID{tls.X25519MLKEM768}, tls.X25519MLKEM768)
	assertPolicy(t, r, StatusCompliant, true, EventCompliant, SeverityCompliant)
}

func TestHybridRequiredWithClassical(t *testing.T) {
	r := EvaluatePolicy(HybridRequired, []tls.CurveID{tls.X25519MLKEM768}, tls.X25519)
	assertPolicy(t, r, StatusViolation, false, EventViolation, SeverityAlert)
}

func TestHybridPreferredWithHybrid(t *testing.T) {
	r := EvaluatePolicy(HybridPreferred, []tls.CurveID{tls.X25519MLKEM768}, tls.X25519MLKEM768)
	assertPolicy(t, r, StatusCompliant, true, EventCompliant, SeverityCompliant)
}

func TestHybridPreferredWithClassical(t *testing.T) {
	r := EvaluatePolicy(HybridPreferred, []tls.CurveID{tls.X25519MLKEM768}, tls.X25519)
	assertPolicy(t, r, StatusFallback, true, EventFallback, SeverityWarning)
}

func TestLegacyAllowedWithHybrid(t *testing.T) {
	r := EvaluatePolicy(LegacyAllowed, []tls.CurveID{tls.X25519}, tls.X25519MLKEM768)
	assertPolicy(t, r, StatusCompliant, true, EventCompliant, SeverityCompliant)
}

func TestLegacyAllowedWithClassical(t *testing.T) {
	r := EvaluatePolicy(LegacyAllowed, []tls.CurveID{tls.X25519}, tls.X25519)
	assertPolicy(t, r, StatusCompliant, true, EventCompliant, SeverityCompliant)
}

func TestParsePolicyMode(t *testing.T) {
	for _, s := range []string{"HYBRID_REQUIRED", "hybrid_required", " Hybrid_Preferred "} {
		if _, err := ParsePolicyMode(s); err != nil {
			t.Fatalf("ParsePolicyMode(%q): %v", s, err)
		}
	}
	if _, err := ParsePolicyMode("INVALID"); err == nil {
		t.Fatal("expected error for invalid policy")
	}
}

func TestNewSecurityEvent(t *testing.T) {
	r := EvaluatePolicy(HybridRequired, []tls.CurveID{tls.X25519MLKEM768}, tls.X25519)
	ev := NewSecurityEvent("hybrid", r)
	if ev.Type != EventViolation {
		t.Fatalf("Type = %q, want %s", ev.Type, EventViolation)
	}
	if ev.Severity != SeverityAlert {
		t.Fatalf("Severity = %q, want %s", ev.Severity, SeverityAlert)
	}
	if ev.Provider != "hybrid" {
		t.Fatalf("Provider = %q", ev.Provider)
	}
	if ev.Policy != string(HybridRequired) {
		t.Fatalf("Policy = %q", ev.Policy)
	}
	if ev.NegotiatedGroup != "X25519" {
		t.Fatalf("NegotiatedGroup = %q", ev.NegotiatedGroup)
	}
	if ev.Timestamp == "" {
		t.Fatal("Timestamp empty")
	}
}

func TestEventStoreBound(t *testing.T) {
	store := NewEventStore(3)
	for i := 0; i < 5; i++ {
		store.Add(SecurityEvent{Type: EventCompliant, Message: string(rune('a' + i))})
	}
	if store.Len() != 3 {
		t.Fatalf("Len = %d, want 3", store.Len())
	}
	snap := store.Snapshot()
	if snap[0].Message != "c" || snap[2].Message != "e" {
		t.Fatalf("snapshot = %+v, want oldest dropped", snap)
	}
}

func assertPolicy(t *testing.T, r PolicyResult, status string, compliant bool, eventType, severity string) {
	t.Helper()
	if r.Status != status {
		t.Fatalf("Status = %q, want %q", r.Status, status)
	}
	if r.Compliant != compliant {
		t.Fatalf("Compliant = %v, want %v", r.Compliant, compliant)
	}
	if r.EventType != eventType {
		t.Fatalf("EventType = %q, want %q", r.EventType, eventType)
	}
	if r.Severity != severity {
		t.Fatalf("Severity = %q, want %q", r.Severity, severity)
	}
}
