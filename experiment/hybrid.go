package experiment

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
)

const (
	hybridInfoLabel = "pq-tls-demo/educational-hybrid-combiner/v1"
	hybridKeySize   = 32
	componentSize   = 32
)

// HybridExperiment is an educational hybrid-combination model.
//
// It demonstrates that a combined secret can depend on both a classical and a
// post-quantum component. It is NOT a reproduction of Go TLS's internal
// X25519MLKEM768 key schedule, and it does NOT extract ML-KEM secrets from
// tls.ConnectionState.
type HybridExperiment struct {
	ClassicalSecret []byte
	PQSecret        []byte
	HybridSecret    []byte
}

// RunHybridExperiment generates independent classical and PQ-like secret
// components and combines them with an educational HKDF-based combiner.
func RunHybridExperiment() (*HybridExperiment, error) {
	classical := make([]byte, componentSize)
	pq := make([]byte, componentSize)
	if _, err := io.ReadFull(rand.Reader, classical); err != nil {
		return nil, fmt.Errorf("generate classical component: %w", err)
	}
	if _, err := io.ReadFull(rand.Reader, pq); err != nil {
		return nil, fmt.Errorf("generate PQ component: %w", err)
	}

	hybrid, err := CombineHybridSecrets(classical, pq)
	if err != nil {
		return nil, err
	}

	return &HybridExperiment{
		ClassicalSecret: classical,
		PQSecret:        pq,
		HybridSecret:    hybrid,
	}, nil
}

// CombineHybridSecrets implements an educational hybrid-combination model:
//
//	hybridSecret = HKDF-SHA256(ikm = classicalSecret || pqSecret)
//
// This is a demonstration combiner, not the TLS X25519MLKEM768 specification.
func CombineHybridSecrets(classicalSecret, pqSecret []byte) ([]byte, error) {
	ikm := make([]byte, 0, len(classicalSecret)+len(pqSecret))
	ikm = append(ikm, classicalSecret...)
	ikm = append(ikm, pqSecret...)
	defer zero(ikm)

	out, err := hkdf.Key(sha256.New, ikm, nil, hybridInfoLabel, hybridKeySize)
	if err != nil {
		return nil, fmt.Errorf("hybrid combiner HKDF: %w", err)
	}
	return out, nil
}

// ClassicalOnlyReconstruction attempts to reconstruct the hybrid secret using
// a recovered classical component and a missing/dummy PQ component.
//
// The result must not equal the original hybrid secret when the PQ component
// is wrong — demonstrating classical-only recovery is insufficient.
func ClassicalOnlyReconstruction(recoveredClassical []byte) ([]byte, error) {
	dummyPQ := make([]byte, componentSize) // all zeros: missing PQ component
	return CombineHybridSecrets(recoveredClassical, dummyPQ)
}

// SecretsEqual reports whether two secrets are identical in constant time.
func SecretsEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// Zero clears sensitive hybrid experiment buffers after use.
func (e *HybridExperiment) Zero() {
	if e == nil {
		return
	}
	zero(e.ClassicalSecret)
	zero(e.PQSecret)
	zero(e.HybridSecret)
}
