package experiment

import (
	"fmt"
	"strings"
)

// Result holds human-readable outcomes for the controlled HNDL demonstration.
// Secret material is never included.
type Result struct {
	ClassicalAgreement       bool
	ClassicalSecretRecovery  bool
	ClassicalMessageRecovery bool
	HybridGeneration         bool
	ClassicalOnlyDifferent   bool // true when classical-only != hybrid (expected)
}

// RunControlledHNDL executes the full controlled HNDL demonstration without
// printing or returning secret material.
func RunControlledHNDL() (Result, error) {
	var r Result

	classical, err := RunClassicalExperiment()
	if err != nil {
		return r, fmt.Errorf("classical experiment: %w", err)
	}
	defer classical.Zero()

	// Agreement: Alice and Bob sides match (already checked in RunClassicalExperiment).
	r.ClassicalAgreement = true

	recovered, err := RecoverClassicalSharedSecret(classical.AlicePrivate, classical.BobPublic)
	if err != nil {
		return r, fmt.Errorf("classical recovery: %w", err)
	}
	r.ClassicalSecretRecovery = SecretsEqual(recovered, classical.SharedSecret)
	zero(recovered)
	if !r.ClassicalSecretRecovery {
		return r, fmt.Errorf("classical secret recovery failed")
	}

	plaintext, err := RecoverAndDecryptClassical(classical)
	if err != nil {
		return r, fmt.Errorf("message recovery: %w", err)
	}
	r.ClassicalMessageRecovery = string(plaintext) == DemoPlaintext()
	if !r.ClassicalMessageRecovery {
		return r, fmt.Errorf("recorded message recovery failed")
	}

	hybrid, err := RunHybridExperiment()
	if err != nil {
		return r, fmt.Errorf("hybrid experiment: %w", err)
	}
	defer hybrid.Zero()
	r.HybridGeneration = len(hybrid.HybridSecret) > 0

	reconstructed, err := ClassicalOnlyReconstruction(hybrid.ClassicalSecret)
	if err != nil {
		return r, fmt.Errorf("classical-only reconstruction: %w", err)
	}
	defer zero(reconstructed)
	r.ClassicalOnlyDifferent = !SecretsEqual(reconstructed, hybrid.HybridSecret)
	if !r.ClassicalOnlyDifferent {
		return r, fmt.Errorf("classical-only reconstruction unexpectedly matched hybrid secret")
	}

	return r, nil
}

// FormatReport renders a high-level experiment report with no secrets.
func FormatReport(r Result) string {
	var b strings.Builder
	b.WriteString("HNDL Controlled Experiment\n")
	b.WriteString("==========================\n\n")
	b.WriteString("This is a controlled secret-recovery experiment.\n")
	b.WriteString("It is NOT a real TLS passive decryption attack.\n\n")

	b.WriteString("Classical X25519 experiment\n")
	b.WriteString(fmt.Sprintf("  Shared secret agreement: %s\n", passFail(r.ClassicalAgreement)))
	b.WriteString(fmt.Sprintf("  Controlled secret recovery: %s\n", passFail(r.ClassicalSecretRecovery)))
	b.WriteString(fmt.Sprintf("  Recorded message recovery: %s\n", passFail(r.ClassicalMessageRecovery)))
	b.WriteString("\n")

	b.WriteString("Hybrid dependency experiment\n")
	b.WriteString(fmt.Sprintf("  Hybrid secret generation: %s\n", passFail(r.HybridGeneration)))
	if r.ClassicalOnlyDifferent {
		b.WriteString("  Classical-only reconstruction: DIFFERENT SECRET (expected)\n")
	} else {
		b.WriteString("  Classical-only reconstruction: UNEXPECTED MATCH\n")
	}
	b.WriteString("\n")

	b.WriteString("Conclusion:\n")
	b.WriteString("  Classical-only recovery can reproduce the classical\n")
	b.WriteString("  derived secret in this controlled experiment.\n\n")
	b.WriteString("  The hybrid demonstration requires both the classical\n")
	b.WriteString("  and post-quantum components to reproduce the combined\n")
	b.WriteString("  secret.\n")
	return b.String()
}

func passFail(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}
