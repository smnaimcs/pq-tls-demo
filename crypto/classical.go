package crypto

import "crypto/tls"

// ClassicalProvider configures TLS for classical X25519 key exchange only.
type ClassicalProvider struct{}

func (ClassicalProvider) ID() string {
	return "classical"
}

func (ClassicalProvider) CurvePreferences() []tls.CurveID {
	return []tls.CurveID{
		tls.X25519,
	}
}

func (ClassicalProvider) QuantumRisk() QuantumRisk {
	return RiskClassical
}

func (ClassicalProvider) Description() string {
	return "Classical X25519 key exchange"
}
