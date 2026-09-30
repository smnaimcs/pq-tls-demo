package crypto

import (
	"crypto/tls"
	"fmt"
	"time"
)

const InventoryVersion = "1.0"

// CryptoAsset represents one cryptographic mechanism in the inventory.
// This is a CBOM-inspired model, not a CycloneDX schema claim.
type CryptoAsset struct {
	Name          string `json:"name"`
	Category      string `json:"category"`
	Role          string `json:"role"`
	SecurityClass string `json:"security_class,omitempty"`
	QuantumRisk   string `json:"quantum_risk,omitempty"`
	Source        string `json:"source"`
	Description   string `json:"description,omitempty"`
}

// NegotiatedInfo reports whether negotiated TLS state is available.
// Negotiated assets are never fabricated when Available is false.
type NegotiatedInfo struct {
	Available bool `json:"available"`
}

// CryptoInventory is a CBOM-inspired cryptographic inventory for this prototype.
// It is not claimed to be a standards-compliant CycloneDX CBOM.
type CryptoInventory struct {
	Version     string         `json:"version"`
	GeneratedAt string         `json:"generated_at"`
	Provider    string         `json:"provider"`
	Negotiated  NegotiatedInfo `json:"negotiated"`
	Assets      []CryptoAsset  `json:"assets"`
}

// ClassifyKeyAgreement maps a TLS CurveID to a CryptoAsset classification.
// Unsupported curves are classified as unknown — never silently as classical.
func ClassifyKeyAgreement(curve tls.CurveID, source, role string) CryptoAsset {
	switch curve {
	case tls.X25519:
		return CryptoAsset{
			Name:          "X25519",
			Category:      "key_agreement",
			Role:          role,
			SecurityClass: "classical",
			QuantumRisk:   "vulnerable",
			Source:        source,
			Description: "Classical elliptic-curve Diffie-Hellman key agreement (X25519). " +
				"It is not designed to resist a sufficiently capable cryptographically " +
				"relevant quantum computer. This classification does not claim that an " +
				"actual quantum attack currently exists.",
		}
	case tls.X25519MLKEM768:
		return CryptoAsset{
			Name:          "X25519MLKEM768",
			Category:      "key_agreement",
			Role:          role,
			SecurityClass: "hybrid",
			QuantumRisk:   "hybrid",
			Source:        source,
			Description: "Hybrid TLS key agreement combining classical X25519 with " +
				"ML-KEM-768. This classification concerns the key-agreement mechanism " +
				"only; it does not mean that all TLS cryptography is post-quantum.",
		}
	default:
		name := curve.String()
		if name == "" {
			name = fmt.Sprintf("CurveID(%d)", curve)
		}
		return CryptoAsset{
			Name:          name,
			Category:      "key_agreement",
			Role:          role,
			SecurityClass: "unknown",
			QuantumRisk:   "unknown",
			Source:        source,
			Description:   "Unsupported or unrecognized key-agreement group; not silently classified as classical.",
		}
	}
}

// ClassifyCipher maps a negotiated TLS cipher suite to a CryptoAsset.
// The name always comes from tls.CipherSuiteName; it is never hard-coded.
func ClassifyCipher(suite uint16) CryptoAsset {
	name := tls.CipherSuiteName(suite)
	if name == "" {
		name = fmt.Sprintf("CipherSuite(0x%04x)", suite)
	}
	return CryptoAsset{
		Name:        name,
		Category:    "cipher",
		Role:        "tls_record_protection",
		Source:      "negotiated",
		Description: "TLS 1.3 record-layer cipher suite negotiated for this connection.",
	}
}

// BuildConfiguredAssets derives configured key-agreement assets from a provider.
func BuildConfiguredAssets(provider CryptoProvider) []CryptoAsset {
	curves := provider.CurvePreferences()
	assets := make([]CryptoAsset, 0, len(curves))
	for _, curve := range curves {
		assets = append(assets, ClassifyKeyAgreement(curve, "configured", "configured_key_agreement"))
	}
	return assets
}

// BuildInventory builds a CBOM-inspired inventory from the configured provider
// and, when available, the actual tls.ConnectionState.
//
// Configured assets always come from provider.CurvePreferences().
// Negotiated assets come only from state (CurveID and CipherSuite).
// If state is nil, negotiated information is marked unavailable and no
// negotiated assets are invented.
func BuildInventory(provider CryptoProvider, state *tls.ConnectionState) CryptoInventory {
	inv := CryptoInventory{
		Version:     InventoryVersion,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Provider:    provider.ID(),
		Negotiated: NegotiatedInfo{
			Available: state != nil,
		},
		Assets: BuildConfiguredAssets(provider),
	}

	if state == nil {
		return inv
	}

	inv.Assets = append(inv.Assets,
		ClassifyKeyAgreement(state.CurveID, "negotiated", "negotiated_key_agreement"),
		ClassifyCipher(state.CipherSuite),
	)
	return inv
}
