// Package experiment implements a controlled educational HNDL (Harvest Now,
// Decrypt Later) secret-recovery demonstration.
//
// This is NOT a real TLS passive decryption attack. TLS 1.3 uses ephemeral
// Diffie-Hellman; the server certificate private key does not recover an
// X25519 session secret. Instead, this package deliberately retains an
// ephemeral classical secret inside a test harness for pedagogical purposes.
//
// Do not integrate deliberate secret retention into the normal TLS server path.
package experiment

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
)

const (
	demoInfoLabel = "pq-tls-demo/hndl-controlled-experiment/v1"
	demoPlaintext = "historical banking transaction"
	aeadKeySize   = 32
)

// ClassicalExperiment holds deliberately retained ephemeral material for the
// controlled secret-recovery experiment. Secrets must never be printed, logged,
// written to disk, or sent over the network.
type ClassicalExperiment struct {
	AlicePrivate []byte
	AlicePublic  []byte
	BobPrivate   []byte
	BobPublic    []byte
	SharedSecret []byte
	Ciphertext   []byte
	Nonce        []byte
}

// RunClassicalExperiment performs an ephemeral X25519 exchange, retains the
// Alice private value in memory, encrypts a demo message with a key derived
// from the shared secret, and returns the experiment state.
func RunClassicalExperiment() (*ClassicalExperiment, error) {
	curve := ecdh.X25519()

	alicePriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate Alice key: %w", err)
	}
	bobPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate Bob key: %w", err)
	}

	aliceShared, err := alicePriv.ECDH(bobPriv.PublicKey())
	if err != nil {
		return nil, fmt.Errorf("Alice ECDH: %w", err)
	}
	bobShared, err := bobPriv.ECDH(alicePriv.PublicKey())
	if err != nil {
		return nil, fmt.Errorf("Bob ECDH: %w", err)
	}
	if subtle.ConstantTimeCompare(aliceShared, bobShared) != 1 {
		return nil, errors.New("X25519 shared secrets do not agree")
	}

	key, err := DeriveAEADKey(aliceShared)
	if err != nil {
		return nil, err
	}
	ciphertext, nonce, err := Encrypt(key, []byte(demoPlaintext))
	if err != nil {
		zero(key)
		return nil, err
	}
	zero(key)

	return &ClassicalExperiment{
		AlicePrivate: append([]byte(nil), alicePriv.Bytes()...),
		AlicePublic:  append([]byte(nil), alicePriv.PublicKey().Bytes()...),
		BobPrivate:   append([]byte(nil), bobPriv.Bytes()...),
		BobPublic:    append([]byte(nil), bobPriv.PublicKey().Bytes()...),
		SharedSecret: append([]byte(nil), aliceShared...),
		Ciphertext:   ciphertext,
		Nonce:        nonce,
	}, nil
}

// RecoverClassicalSharedSecret recomputes an X25519 shared secret from a
// deliberately retained private value and the peer public key.
//
// This does not break X25519. Recovery is trivial because the private value
// was intentionally retained by the test harness.
func RecoverClassicalSharedSecret(recoveredPrivate, peerPublic []byte) ([]byte, error) {
	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(recoveredPrivate)
	if err != nil {
		return nil, fmt.Errorf("import recovered private key: %w", err)
	}
	pub, err := curve.NewPublicKey(peerPublic)
	if err != nil {
		return nil, fmt.Errorf("import peer public key: %w", err)
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("recover ECDH: %w", err)
	}
	return shared, nil
}

// DeriveAEADKey derives a 32-byte AES-256-GCM key from a shared secret using
// HKDF-SHA256. This is an application-level demonstration KDF, not the TLS
// 1.3 key schedule.
func DeriveAEADKey(sharedSecret []byte) ([]byte, error) {
	key, err := hkdf.Key(sha256.New, sharedSecret, nil, demoInfoLabel, aeadKeySize)
	if err != nil {
		return nil, fmt.Errorf("HKDF: %w", err)
	}
	return key, nil
}

// Encrypt seals plaintext with AES-256-GCM using a random nonce.
func Encrypt(key, plaintext []byte) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = aead.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// Decrypt opens AES-256-GCM ciphertext.
func Decrypt(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, nil)
}

// RecoverAndDecryptClassical uses the deliberately retained Alice private
// value to recover the shared secret, re-derive the AEAD key, and decrypt the
// recorded ciphertext.
func RecoverAndDecryptClassical(exp *ClassicalExperiment) ([]byte, error) {
	recovered, err := RecoverClassicalSharedSecret(exp.AlicePrivate, exp.BobPublic)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(recovered, exp.SharedSecret) != 1 {
		zero(recovered)
		return nil, errors.New("recovered shared secret does not match original")
	}

	key, err := DeriveAEADKey(recovered)
	zero(recovered)
	if err != nil {
		return nil, err
	}
	defer zero(key)

	return Decrypt(key, exp.Nonce, exp.Ciphertext)
}

// Zero clears sensitive experiment buffers after use (best-effort; not a
// formal memory-wiping guarantee).
func (e *ClassicalExperiment) Zero() {
	if e == nil {
		return
	}
	zero(e.AlicePrivate)
	zero(e.BobPrivate)
	zero(e.SharedSecret)
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// DemoPlaintext returns the fixed educational plaintext used by the experiment.
func DemoPlaintext() string {
	return demoPlaintext
}
