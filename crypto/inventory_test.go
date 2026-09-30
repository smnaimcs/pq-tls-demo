package crypto

import (
	"crypto/tls"
	"testing"
)

func TestClassifyKeyAgreementX25519(t *testing.T) {
	asset := ClassifyKeyAgreement(tls.X25519, "configured", "configured_key_agreement")

	if asset.Name != "X25519" {
		t.Fatalf("Name = %q, want X25519", asset.Name)
	}
	if asset.Category != "key_agreement" {
		t.Fatalf("Category = %q, want key_agreement", asset.Category)
	}
	if asset.SecurityClass != "classical" {
		t.Fatalf("SecurityClass = %q, want classical", asset.SecurityClass)
	}
	if asset.QuantumRisk != "vulnerable" {
		t.Fatalf("QuantumRisk = %q, want vulnerable", asset.QuantumRisk)
	}
	if asset.Source != "configured" {
		t.Fatalf("Source = %q, want configured", asset.Source)
	}
}

func TestClassifyKeyAgreementX25519MLKEM768(t *testing.T) {
	asset := ClassifyKeyAgreement(tls.X25519MLKEM768, "negotiated", "negotiated_key_agreement")

	if asset.Name != "X25519MLKEM768" {
		t.Fatalf("Name = %q, want X25519MLKEM768", asset.Name)
	}
	if asset.Category != "key_agreement" {
		t.Fatalf("Category = %q, want key_agreement", asset.Category)
	}
	if asset.SecurityClass != "hybrid" {
		t.Fatalf("SecurityClass = %q, want hybrid", asset.SecurityClass)
	}
	if asset.QuantumRisk != "hybrid" {
		t.Fatalf("QuantumRisk = %q, want hybrid", asset.QuantumRisk)
	}
	if asset.Source != "negotiated" {
		t.Fatalf("Source = %q, want negotiated", asset.Source)
	}
}

func TestClassifyKeyAgreementUnknown(t *testing.T) {
	const unknownCurve tls.CurveID = 0xDEAD
	asset := ClassifyKeyAgreement(unknownCurve, "negotiated", "negotiated_key_agreement")

	if asset.SecurityClass == "classical" || asset.SecurityClass == "hybrid" {
		t.Fatalf("unknown curve silently classified as %q", asset.SecurityClass)
	}
	if asset.SecurityClass != "unknown" {
		t.Fatalf("SecurityClass = %q, want unknown", asset.SecurityClass)
	}
	if asset.QuantumRisk != "unknown" {
		t.Fatalf("QuantumRisk = %q, want unknown", asset.QuantumRisk)
	}
	if asset.Name == "X25519" || asset.Name == "X25519MLKEM768" {
		t.Fatalf("unknown curve name = %q, must not become a known group", asset.Name)
	}
	if asset.Category != "key_agreement" {
		t.Fatalf("Category = %q, want key_agreement", asset.Category)
	}
}

func TestBuildInventoryWithoutConnection(t *testing.T) {
	provider := HybridProvider{}
	inv := BuildInventory(provider, nil)

	if inv.Version != InventoryVersion {
		t.Fatalf("Version = %q, want %q", inv.Version, InventoryVersion)
	}
	if inv.Provider != "hybrid" {
		t.Fatalf("Provider = %q, want hybrid", inv.Provider)
	}
	if inv.Negotiated.Available {
		t.Fatal("Negotiated.Available = true before any handshake")
	}

	configured := findAssets(inv.Assets, "configured", "key_agreement")
	if len(configured) != 1 || configured[0].Name != "X25519MLKEM768" {
		t.Fatalf("configured key agreement = %+v, want X25519MLKEM768", configured)
	}

	negotiated := findAssets(inv.Assets, "negotiated", "")
	if len(negotiated) != 0 {
		t.Fatalf("fabricated negotiated assets before handshake: %+v", negotiated)
	}
}

func TestBuildInventoryHybrid(t *testing.T) {
	provider := HybridProvider{}
	state := &tls.ConnectionState{
		Version:     tls.VersionTLS13,
		CurveID:     tls.X25519MLKEM768,
		CipherSuite: tls.TLS_AES_128_GCM_SHA256,
	}

	inv := BuildInventory(provider, state)
	if !inv.Negotiated.Available {
		t.Fatal("Negotiated.Available = false after handshake")
	}

	configured := findAssets(inv.Assets, "configured", "key_agreement")
	if len(configured) != 1 || configured[0].Name != "X25519MLKEM768" {
		t.Fatalf("configured = %+v, want X25519MLKEM768", configured)
	}

	negotiatedKA := findAssets(inv.Assets, "negotiated", "key_agreement")
	if len(negotiatedKA) != 1 || negotiatedKA[0].Name != "X25519MLKEM768" {
		t.Fatalf("negotiated key agreement = %+v, want X25519MLKEM768", negotiatedKA)
	}
	if negotiatedKA[0].SecurityClass != "hybrid" {
		t.Fatalf("negotiated security_class = %q, want hybrid", negotiatedKA[0].SecurityClass)
	}

	ciphers := findAssets(inv.Assets, "negotiated", "cipher")
	if len(ciphers) != 1 {
		t.Fatalf("cipher assets = %+v, want one negotiated cipher", ciphers)
	}
	if ciphers[0].Name != tls.CipherSuiteName(tls.TLS_AES_128_GCM_SHA256) {
		t.Fatalf("cipher name = %q, want from CipherSuiteName", ciphers[0].Name)
	}
	if ciphers[0].Role != "tls_record_protection" {
		t.Fatalf("cipher role = %q, want tls_record_protection", ciphers[0].Role)
	}
}

func TestBuildInventoryClassical(t *testing.T) {
	provider := ClassicalProvider{}
	state := &tls.ConnectionState{
		Version:     tls.VersionTLS13,
		CurveID:     tls.X25519,
		CipherSuite: tls.TLS_AES_256_GCM_SHA384,
	}

	inv := BuildInventory(provider, state)

	configured := findAssets(inv.Assets, "configured", "key_agreement")
	if len(configured) != 1 || configured[0].Name != "X25519" {
		t.Fatalf("configured = %+v, want X25519", configured)
	}
	if configured[0].QuantumRisk != "vulnerable" {
		t.Fatalf("configured quantum_risk = %q, want vulnerable", configured[0].QuantumRisk)
	}

	negotiatedKA := findAssets(inv.Assets, "negotiated", "key_agreement")
	if len(negotiatedKA) != 1 || negotiatedKA[0].Name != "X25519" {
		t.Fatalf("negotiated key agreement = %+v, want X25519", negotiatedKA)
	}

	ciphers := findAssets(inv.Assets, "negotiated", "cipher")
	if len(ciphers) != 1 || ciphers[0].Name != tls.CipherSuiteName(tls.TLS_AES_256_GCM_SHA384) {
		t.Fatalf("cipher = %+v, want negotiated suite name", ciphers)
	}
}

func findAssets(assets []CryptoAsset, source, category string) []CryptoAsset {
	var out []CryptoAsset
	for _, a := range assets {
		if a.Source != source {
			continue
		}
		if category != "" && a.Category != category {
			continue
		}
		out = append(out, a)
	}
	return out
}
