package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// TestHybridTLSHandshake verifies the Iteration 1 invariant:
// a TLS 1.3 connection must negotiate X25519MLKEM768, not classical X25519
// or any other group. This prevents the demo from silently becoming a
// classical TLS demonstration.
func TestHybridTLSHandshake(t *testing.T) {
	cert, err := generateLocalhostCert()
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.Error(w, "no TLS state", http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, r.TLS.CurveID.String())
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	server := &http.Server{
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{
				tls.X25519MLKEM768,
			},
		},
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ServeTLS(ln, "", "")
	}()
	defer server.Close()

	// Wait briefly for the listener to accept.
	time.Sleep(50 * time.Millisecond)

	clientTLS := &tls.Config{
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
			TLSClientConfig: clientTLS,
		},
		Timeout: 5 * time.Second,
	}

	url := "https://" + ln.Addr().String() + "/"
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("client GET: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	if resp.TLS == nil {
		t.Fatal("response has no TLS connection state")
	}
	state := resp.TLS

	if state.Version != tls.VersionTLS13 {
		t.Fatalf("TLS version = %s (%#x), want TLS 1.3",
			tls.VersionName(state.Version), state.Version)
	}

	if state.CurveID != tls.X25519MLKEM768 {
		t.Fatalf("negotiated CurveID = %v (%d), want X25519MLKEM768 (%d); "+
			"classical X25519 or any other group is a test failure",
			state.CurveID, state.CurveID, tls.X25519MLKEM768)
	}

	if string(body) != "X25519MLKEM768" {
		t.Fatalf("server reported group %q, want X25519MLKEM768", body)
	}

	t.Logf("OK: TLS %s, Cipher Suite %s, Key Exchange Group %s",
		tls.VersionName(state.Version),
		tls.CipherSuiteName(state.CipherSuite),
		state.CurveID.String())
}
