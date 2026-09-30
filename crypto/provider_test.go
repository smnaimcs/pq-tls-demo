package crypto

import (
	"crypto/tls"
	"testing"
)

func TestClassicalProvider(t *testing.T) {
	p := ClassicalProvider{}

	if got := p.ID(); got != "classical" {
		t.Fatalf("ID() = %q, want classical", got)
	}
	if got := p.Description(); got != "Classical X25519 key exchange" {
		t.Fatalf("Description() = %q, want Classical X25519 key exchange", got)
	}
	if got := p.QuantumRisk(); got != RiskClassical {
		t.Fatalf("QuantumRisk() = %v, want RiskClassical", got)
	}

	curves := p.CurvePreferences()
	if len(curves) != 1 || curves[0] != tls.X25519 {
		t.Fatalf("CurvePreferences() = %v, want [X25519]", curves)
	}
}

func TestHybridProvider(t *testing.T) {
	p := HybridProvider{}

	if got := p.ID(); got != "hybrid" {
		t.Fatalf("ID() = %q, want hybrid", got)
	}
	if got := p.Description(); got != "Hybrid X25519 + ML-KEM-768 key exchange" {
		t.Fatalf("Description() = %q, want Hybrid X25519 + ML-KEM-768 key exchange", got)
	}
	if got := p.QuantumRisk(); got != RiskHybrid {
		t.Fatalf("QuantumRisk() = %v, want RiskHybrid", got)
	}

	curves := p.CurvePreferences()
	if len(curves) != 1 || curves[0] != tls.X25519MLKEM768 {
		t.Fatalf("CurvePreferences() = %v, want [X25519MLKEM768]", curves)
	}
}

func TestNewProvider(t *testing.T) {
	t.Run("classical", func(t *testing.T) {
		p, err := NewProvider("classical")
		if err != nil {
			t.Fatalf("NewProvider(classical): %v", err)
		}
		if _, ok := p.(ClassicalProvider); !ok {
			t.Fatalf("NewProvider(classical) type = %T, want ClassicalProvider", p)
		}
	})

	t.Run("hybrid", func(t *testing.T) {
		p, err := NewProvider("hybrid")
		if err != nil {
			t.Fatalf("NewProvider(hybrid): %v", err)
		}
		if _, ok := p.(HybridProvider); !ok {
			t.Fatalf("NewProvider(hybrid) type = %T, want HybridProvider", p)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		p, err := NewProvider("invalid-provider")
		if err == nil {
			t.Fatalf("NewProvider(invalid-provider) = %T, want error", p)
		}
		if p != nil {
			t.Fatalf("NewProvider(invalid-provider) provider = %v, want nil", p)
		}
	})
}
