package crypto

import "crypto/tls"

// HybridProvider configures TLS for hybrid X25519MLKEM768 key exchange only.
type HybridProvider struct{}

func (HybridProvider) ID() string {
	return "hybrid"
}

func (HybridProvider) CurvePreferences() []tls.CurveID {
	return []tls.CurveID{
		tls.X25519MLKEM768,
	}
}

func (HybridProvider) QuantumRisk() QuantumRisk {
	return RiskHybrid
}

func (HybridProvider) Description() string {
	return "Hybrid X25519 + ML-KEM-768 key exchange"
}
