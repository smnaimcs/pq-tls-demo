// Package crypto defines CryptoProvider abstractions for configuration-driven
// TLS cryptographic policy selection.
package crypto

import (
	"crypto/tls"
	"fmt"
	"strings"
)

// QuantumRisk is an application-level classification of a provider's
// quantum-related posture. It is not a formal cryptographic security proof.
type QuantumRisk int

const (
	RiskClassical QuantumRisk = iota
	RiskHybrid
)

func (r QuantumRisk) String() string {
	switch r {
	case RiskClassical:
		return "classical"
	case RiskHybrid:
		return "hybrid"
	default:
		return fmt.Sprintf("QuantumRisk(%d)", int(r))
	}
}

// CryptoProvider represents the cryptographic policy for a TLS endpoint.
type CryptoProvider interface {
	ID() string
	CurvePreferences() []tls.CurveID
	QuantumRisk() QuantumRisk
	Description() string
}

// NewProvider selects a CryptoProvider by configuration ID.
// Unknown IDs return an error; there is no silent fallback.
func NewProvider(id string) (CryptoProvider, error) {
	switch strings.ToLower(strings.TrimSpace(id)) {
	case "classical":
		return ClassicalProvider{}, nil
	case "hybrid":
		return HybridProvider{}, nil
	default:
		return nil, fmt.Errorf("unknown crypto provider %q", id)
	}
}

// FormatCurveIDs renders CurveID values for startup and logging output.
func FormatCurveIDs(ids []tls.CurveID) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = id.String()
	}
	return "[" + strings.Join(parts, " ") + "]"
}
