// pq-tls-demo — Iteration 1: Hybrid TLS Handshake Baseline
//
// Minimal HTTPS client/server that performs a real TLS 1.3 handshake using
// the hybrid key-exchange group X25519MLKEM768 (Go standard library only).
//
// X25519MLKEM768 is a NamedGroup / CurveID, not a cipher suite.
// Cipher suites (e.g. TLS_AES_128_GCM_SHA256) are negotiated separately.
package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"
)

const listenAddr = "127.0.0.1:8443"

func main() {
	log.SetFlags(0)

	fmt.Printf("Go version: %s\n", runtime.Version())
	fmt.Println("Configured key exchange: X25519MLKEM768")

	// Compile-time reference: if this Go toolchain lacks X25519MLKEM768,
	// the program will not build. Do not fall back to classical X25519.
	_ = tls.X25519MLKEM768

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <server|client>\n", os.Args[0])
		os.Exit(2)
	}

	switch os.Args[1] {
	case "server":
		if err := runServer(); err != nil {
			log.Fatalf("server error: %v", err)
		}
	case "client":
		if err := runClient(); err != nil {
			log.Fatalf("client error: %v", err)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q; use server or client\n", os.Args[1])
		os.Exit(2)
	}
}

func hybridTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		// Require hybrid key exchange only. No classical X25519 fallback
		// in this iteration — the experiment must be deterministic.
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768,
		},
	}
}

func formatTLSInfo(state *tls.ConnectionState) string {
	return fmt.Sprintf(
		"TLS Version: %s\nCipher Suite: %s\nKey Exchange Group: %s",
		tls.VersionName(state.Version),
		tls.CipherSuiteName(state.CipherSuite),
		state.CurveID.String(),
	)
}

func verifyNegotiatedGroup(state *tls.ConnectionState) {
	if state.CurveID != tls.X25519MLKEM768 {
		log.Printf(
			"ERROR: expected X25519MLKEM768, negotiated %v (NEGOTIATION FAILURE)",
			state.CurveID,
		)
	} else {
		log.Println("SUCCESS: X25519MLKEM768 negotiated")
	}
}

func runServer() error {
	cert, err := generateLocalhostCert()
	if err != nil {
		return fmt.Errorf("certificate: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.Error(w, "no TLS connection state", http.StatusInternalServerError)
			return
		}
		state := r.TLS

		log.Println("Connection received")
		log.Println(formatTLSInfo(state))
		verifyNegotiatedGroup(state)

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, formatTLSInfo(state))
	})

	server := &http.Server{
		Addr:      listenAddr,
		Handler:   mux,
		TLSConfig: hybridTLSConfig(cert),
	}

	log.Printf("Server listening on https://%s\n", listenAddr)
	// Empty cert/key paths: certificates come from TLSConfig.Certificates.
	return server.ListenAndServeTLS("", "")
}

func runClient() error {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768,
		},
		// DEMONSTRATION ONLY.
		// Do not use InsecureSkipVerify in production.
		InsecureSkipVerify: true,
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}

	resp, err := client.Get("https://" + listenAddr + "/")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	fmt.Println("Connected successfully")
	fmt.Println()
	fmt.Println("Server-reported TLS information:")
	fmt.Print(string(body))

	if resp.TLS != nil {
		fmt.Println()
		fmt.Printf("Client-observed negotiated group: %s\n", resp.TLS.CurveID.String())
		fmt.Println("Client-observed TLS information:")
		fmt.Println(formatTLSInfo(resp.TLS))
		verifyNegotiatedGroup(resp.TLS)

		if resp.TLS.CurveID != tls.X25519MLKEM768 {
			return fmt.Errorf("client negotiated %v, want X25519MLKEM768", resp.TLS.CurveID)
		}
	} else {
		return fmt.Errorf("client response has no TLS connection state")
	}

	// Cross-check that the server body also reports the hybrid group.
	if !strings.Contains(string(body), "X25519MLKEM768") {
		return fmt.Errorf("server body did not report X25519MLKEM768:\n%s", body)
	}
	return nil
}
