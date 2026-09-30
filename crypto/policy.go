package crypto

import (
	"crypto/tls"
	"fmt"
	"strings"
	"time"
)

// CryptoPolicyMode is an application-level policy classification.
// It is not a TLS protocol mode.
type CryptoPolicyMode string

const (
	HybridRequired  CryptoPolicyMode = "HYBRID_REQUIRED"
	HybridPreferred CryptoPolicyMode = "HYBRID_PREFERRED"
	LegacyAllowed   CryptoPolicyMode = "LEGACY_ALLOWED"
)

// Policy status values returned by EvaluatePolicy.
const (
	StatusCompliant = "compliant"
	StatusFallback  = "fallback"
	StatusViolation = "violation"
)

// Security event types.
const (
	EventCompliant = "CRYPTO_POLICY_COMPLIANT"
	EventFallback  = "CRYPTO_POLICY_FALLBACK"
	EventViolation = "CRYPTO_POLICY_VIOLATION"
)

// Severity levels for security events.
const (
	SeverityCompliant = "COMPLIANT"
	SeverityInfo      = "INFO"
	SeverityWarning   = "WARNING"
	SeverityAlert     = "ALERT"
)

// ParsePolicyMode validates and returns a CryptoPolicyMode.
func ParsePolicyMode(s string) (CryptoPolicyMode, error) {
	mode := CryptoPolicyMode(strings.ToUpper(strings.TrimSpace(s)))
	switch mode {
	case HybridRequired, HybridPreferred, LegacyAllowed:
		return mode, nil
	default:
		return "", fmt.Errorf("unknown crypto policy %q; want HYBRID_REQUIRED, HYBRID_PREFERRED, or LEGACY_ALLOWED", s)
	}
}

// PolicyResult is the outcome of evaluating a negotiated group against policy.
type PolicyResult struct {
	Mode            CryptoPolicyMode
	ConfiguredGroup tls.CurveID
	NegotiatedGroup tls.CurveID
	Status          string
	Compliant       bool
	Reason          string
	EventType       string
	Severity        string
}

// SecurityEvent is a structured, non-secret record of a policy evaluation.
// It must never contain private keys, shared secrets, or TLS key material.
type SecurityEvent struct {
	Timestamp       string `json:"timestamp"`
	Type            string `json:"type"`
	Severity        string `json:"severity"`
	Provider        string `json:"provider"`
	Policy          string `json:"policy"`
	ConfiguredGroup string `json:"configured_group"`
	NegotiatedGroup string `json:"negotiated_group"`
	Message         string `json:"message"`
}

// EvaluatePolicy compares the negotiated key-agreement group against the
// configured application policy. It reports a policy outcome, not an attack.
func EvaluatePolicy(mode CryptoPolicyMode, configured []tls.CurveID, negotiated tls.CurveID) PolicyResult {
	var configuredGroup tls.CurveID
	if len(configured) > 0 {
		configuredGroup = configured[0]
	}

	result := PolicyResult{
		Mode:            mode,
		ConfiguredGroup: configuredGroup,
		NegotiatedGroup: negotiated,
	}

	hybrid := negotiated == tls.X25519MLKEM768
	classical := negotiated == tls.X25519

	switch mode {
	case HybridRequired:
		if hybrid {
			result.Status = StatusCompliant
			result.Compliant = true
			result.EventType = EventCompliant
			result.Severity = SeverityCompliant
			result.Reason = "negotiated X25519MLKEM768 satisfies HYBRID_REQUIRED"
			return result
		}
		result.Status = StatusViolation
		result.Compliant = false
		result.EventType = EventViolation
		result.Severity = SeverityAlert
		result.Reason = fmt.Sprintf("negotiated %s violates HYBRID_REQUIRED (expected X25519MLKEM768); this is a policy violation, not proof of an attack", negotiated)
		return result

	case HybridPreferred:
		if hybrid {
			result.Status = StatusCompliant
			result.Compliant = true
			result.EventType = EventCompliant
			result.Severity = SeverityCompliant
			result.Reason = "negotiated X25519MLKEM768 satisfies preferred hybrid policy"
			return result
		}
		if classical {
			result.Status = StatusFallback
			result.Compliant = true // permitted by policy
			result.EventType = EventFallback
			result.Severity = SeverityWarning
			result.Reason = "negotiated X25519 under HYBRID_PREFERRED: allowed fallback, preferred policy not selected"
			return result
		}
		result.Status = StatusViolation
		result.Compliant = false
		result.EventType = EventViolation
		result.Severity = SeverityAlert
		result.Reason = fmt.Sprintf("negotiated unsupported group %s under HYBRID_PREFERRED", negotiated)
		return result

	case LegacyAllowed:
		if hybrid || classical {
			result.Status = StatusCompliant
			result.Compliant = true
			result.EventType = EventCompliant
			result.Severity = SeverityCompliant
			result.Reason = fmt.Sprintf("negotiated %s is permitted by LEGACY_ALLOWED", negotiated)
			return result
		}
		result.Status = StatusViolation
		result.Compliant = false
		result.EventType = EventViolation
		result.Severity = SeverityAlert
		result.Reason = fmt.Sprintf("negotiated unsupported group %s under LEGACY_ALLOWED", negotiated)
		return result

	default:
		result.Status = StatusViolation
		result.Compliant = false
		result.EventType = EventViolation
		result.Severity = SeverityAlert
		result.Reason = fmt.Sprintf("unknown policy mode %q", mode)
		return result
	}
}

// NewSecurityEvent builds a SecurityEvent from a PolicyResult and provider ID.
func NewSecurityEvent(providerID string, result PolicyResult) SecurityEvent {
	return SecurityEvent{
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
		Type:            result.EventType,
		Severity:        result.Severity,
		Provider:        providerID,
		Policy:          string(result.Mode),
		ConfiguredGroup: result.ConfiguredGroup.String(),
		NegotiatedGroup: result.NegotiatedGroup.String(),
		Message:         result.Reason,
	}
}
