package experiment

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"io"
	"testing"
)

func TestX25519SharedSecretAgreement(t *testing.T) {
	exp, err := RunClassicalExperiment()
	if err != nil {
		t.Fatalf("RunClassicalExperiment: %v", err)
	}
	defer exp.Zero()

	recoveredFromBob, err := RecoverClassicalSharedSecret(exp.BobPrivate, exp.AlicePublic)
	if err != nil {
		t.Fatalf("Bob-side recompute: %v", err)
	}
	defer zero(recoveredFromBob)

	if subtle.ConstantTimeCompare(exp.SharedSecret, recoveredFromBob) != 1 {
		t.Fatal("Alice shared secret != Bob shared secret")
	}
}

func TestClassicalSecretRecovery(t *testing.T) {
	exp, err := RunClassicalExperiment()
	if err != nil {
		t.Fatalf("RunClassicalExperiment: %v", err)
	}
	defer exp.Zero()

	recovered, err := RecoverClassicalSharedSecret(exp.AlicePrivate, exp.BobPublic)
	if err != nil {
		t.Fatalf("RecoverClassicalSharedSecret: %v", err)
	}
	defer zero(recovered)

	if subtle.ConstantTimeCompare(exp.SharedSecret, recovered) != 1 {
		t.Fatal("recovered shared secret != original shared secret")
	}
}

func TestClassicalDerivedKeyRecovery(t *testing.T) {
	exp, err := RunClassicalExperiment()
	if err != nil {
		t.Fatalf("RunClassicalExperiment: %v", err)
	}
	defer exp.Zero()

	origKey, err := DeriveAEADKey(exp.SharedSecret)
	if err != nil {
		t.Fatalf("DeriveAEADKey(original): %v", err)
	}
	defer zero(origKey)

	recovered, err := RecoverClassicalSharedSecret(exp.AlicePrivate, exp.BobPublic)
	if err != nil {
		t.Fatalf("recover shared: %v", err)
	}
	defer zero(recovered)

	recKey, err := DeriveAEADKey(recovered)
	if err != nil {
		t.Fatalf("DeriveAEADKey(recovered): %v", err)
	}
	defer zero(recKey)

	if subtle.ConstantTimeCompare(origKey, recKey) != 1 {
		t.Fatal("derived keys from original and recovered secrets differ")
	}
}

func TestClassicalRecordedMessageDecryption(t *testing.T) {
	exp, err := RunClassicalExperiment()
	if err != nil {
		t.Fatalf("RunClassicalExperiment: %v", err)
	}
	defer exp.Zero()

	plaintext, err := RecoverAndDecryptClassical(exp)
	if err != nil {
		t.Fatalf("RecoverAndDecryptClassical: %v", err)
	}

	if !bytes.Equal(plaintext, []byte(DemoPlaintext())) {
		t.Fatalf("plaintext = %q, want %q", plaintext, DemoPlaintext())
	}
}

func TestHybridSecretDependsOnBothComponents(t *testing.T) {
	exp, err := RunHybridExperiment()
	if err != nil {
		t.Fatalf("RunHybridExperiment: %v", err)
	}
	defer exp.Zero()

	differentPQ := make([]byte, len(exp.PQSecret))
	if _, err := io.ReadFull(rand.Reader, differentPQ); err != nil {
		t.Fatalf("generate different PQ: %v", err)
	}
	// Ensure it actually differs.
	if SecretsEqual(differentPQ, exp.PQSecret) {
		differentPQ[0] ^= 0xff
	}
	defer zero(differentPQ)

	differentHybrid, err := CombineHybridSecrets(exp.ClassicalSecret, differentPQ)
	if err != nil {
		t.Fatalf("CombineHybridSecrets: %v", err)
	}
	defer zero(differentHybrid)

	if SecretsEqual(exp.HybridSecret, differentHybrid) {
		t.Fatal("hybrid secret unchanged when PQ component changes")
	}
}

func TestClassicalOnlyRecoveryCannotReproduceHybridSecret(t *testing.T) {
	exp, err := RunHybridExperiment()
	if err != nil {
		t.Fatalf("RunHybridExperiment: %v", err)
	}
	defer exp.Zero()

	// Deliberately "recover" only the classical component.
	recoveredClassical := append([]byte(nil), exp.ClassicalSecret...)
	defer zero(recoveredClassical)

	reconstructed, err := ClassicalOnlyReconstruction(recoveredClassical)
	if err != nil {
		t.Fatalf("ClassicalOnlyReconstruction: %v", err)
	}
	defer zero(reconstructed)

	if SecretsEqual(reconstructed, exp.HybridSecret) {
		t.Fatal("classical-only reconstruction unexpectedly equaled hybrid secret")
	}
}
