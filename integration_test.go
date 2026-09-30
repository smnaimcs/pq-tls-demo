package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	democrypto "pq-tls-demo/crypto"
)

func startPolicyServer(t *testing.T, providerID string, policy democrypto.CryptoPolicyMode) (baseURL string, store *postureStore, cleanup func()) {
	t.Helper()

	provider, err := democrypto.NewProvider(providerID)
	if err != nil {
		t.Fatalf("NewProvider(%s): %v", providerID, err)
	}

	cert, err := generateLocalhostCert()
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}

	store = newPostureStore(provider, policy)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.Error(w, "no TLS state", http.StatusInternalServerError)
			return
		}
		result := store.observe(r.TLS)
		fmt.Fprintf(w, "%s\n%s", r.TLS.CurveID.String(), result.Status)
	})
	mux.HandleFunc("/cbom", store.handleCBOM)
	mux.HandleFunc("/status", store.handleStatus)
	mux.HandleFunc("/security-events", store.handleSecurityEvents)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	server := &http.Server{
		Handler:   mux,
		TLSConfig: providerTLSConfig(cert, provider),
	}

	go func() { _ = server.ServeTLS(ln, "", "") }()
	time.Sleep(50 * time.Millisecond)

	cleanup = func() {
		server.Close()
		ln.Close()
	}
	return "https://" + ln.Addr().String(), store, cleanup
}

func dialTLSClient(groups ...tls.CurveID) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS13,
				CurvePreferences:   groups,
				InsecureSkipVerify: true, // DEMONSTRATION ONLY
			},
		},
		Timeout: 5 * time.Second,
	}
}

func getJSON(t *testing.T, client *http.Client, url string, dest any) {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d", url, resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type = %q", ct)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := json.Unmarshal(body, dest); err != nil {
		t.Fatalf("unmarshal %s: %v\n%s", url, err, body)
	}
}

func TestHybridTLSHandshake(t *testing.T) {
	baseURL, store, cleanup := startPolicyServer(t, "hybrid", democrypto.HybridRequired)
	defer cleanup()

	client := dialTLSClient(tls.X25519MLKEM768)
	resp, err := client.Get(baseURL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.TLS == nil || resp.TLS.CurveID != tls.X25519MLKEM768 {
		t.Fatalf("negotiated = %v, want X25519MLKEM768", resp.TLS)
	}
	if resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("version = %s", tls.VersionName(resp.TLS.Version))
	}

	inv := store.inventory()
	if !inv.Negotiated.Available {
		t.Fatal("inventory negotiated unavailable")
	}
	st := store.status()
	if st.PolicyStatus != democrypto.StatusCompliant {
		t.Fatalf("policy_status = %q", st.PolicyStatus)
	}
}

func TestClassicalTLSHandshake(t *testing.T) {
	baseURL, store, cleanup := startPolicyServer(t, "classical", democrypto.LegacyAllowed)
	defer cleanup()

	client := dialTLSClient(tls.X25519)
	resp, err := client.Get(baseURL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.TLS == nil || resp.TLS.CurveID != tls.X25519 {
		t.Fatalf("negotiated = %v, want X25519", resp.TLS)
	}
	st := store.status()
	if st.PolicyStatus != democrypto.StatusCompliant {
		t.Fatalf("policy_status = %q", st.PolicyStatus)
	}
}

func TestCompliantHybridRequired(t *testing.T) {
	baseURL, store, cleanup := startPolicyServer(t, "hybrid", democrypto.HybridRequired)
	defer cleanup()

	client := dialTLSClient(tls.X25519MLKEM768)
	resp, err := client.Get(baseURL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	events := store.events.Snapshot()
	if len(events) == 0 {
		t.Fatal("expected security event")
	}
	last := events[len(events)-1]
	if last.Type != democrypto.EventCompliant {
		t.Fatalf("event type = %q", last.Type)
	}
	if last.Severity != democrypto.SeverityCompliant {
		t.Fatalf("severity = %q", last.Severity)
	}
	if last.NegotiatedGroup != "X25519MLKEM768" {
		t.Fatalf("negotiated_group = %q", last.NegotiatedGroup)
	}

	var status statusResponse
	getJSON(t, client, baseURL+"/status", &status)
	if status.Policy != string(democrypto.HybridRequired) {
		t.Fatalf("policy = %q", status.Policy)
	}
	if status.PolicyStatus != democrypto.StatusCompliant {
		t.Fatalf("policy_status = %q", status.PolicyStatus)
	}
	if status.LastNegotiatedGroup == nil || *status.LastNegotiatedGroup != "X25519MLKEM768" {
		t.Fatalf("last_negotiated_group = %v", status.LastNegotiatedGroup)
	}
}

func TestClassicalPolicyViolation(t *testing.T) {
	// Intentional test configuration: classical provider + HYBRID_REQUIRED.
	// This demonstrates a policy violation, not an attack.
	baseURL, store, cleanup := startPolicyServer(t, "classical", democrypto.HybridRequired)
	defer cleanup()

	client := dialTLSClient(tls.X25519)
	resp, err := client.Get(baseURL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.TLS.CurveID != tls.X25519 {
		t.Fatalf("negotiated = %v", resp.TLS.CurveID)
	}

	events := store.events.Snapshot()
	found := false
	for _, ev := range events {
		if ev.Type == democrypto.EventViolation && ev.NegotiatedGroup == "X25519" {
			found = true
			if ev.Severity != democrypto.SeverityAlert {
				t.Fatalf("severity = %q", ev.Severity)
			}
		}
	}
	if !found {
		t.Fatalf("expected CRYPTO_POLICY_VIOLATION event; got %+v", events)
	}

	var payload struct {
		Events []democrypto.SecurityEvent `json:"events"`
	}
	getJSON(t, client, baseURL+"/security-events", &payload)
	if len(payload.Events) == 0 {
		t.Fatal("empty /security-events")
	}

	st := store.status()
	if st.PolicyStatus != democrypto.StatusViolation {
		t.Fatalf("policy_status = %q, want violation", st.PolicyStatus)
	}
}

func TestHybridPreferredFallback(t *testing.T) {
	// Server offers only classical groups; policy prefers hybrid → fallback.
	baseURL, store, cleanup := startPolicyServer(t, "classical", democrypto.HybridPreferred)
	defer cleanup()

	client := dialTLSClient(tls.X25519)
	resp, err := client.Get(baseURL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	st := store.status()
	if st.PolicyStatus != democrypto.StatusFallback {
		t.Fatalf("policy_status = %q, want fallback", st.PolicyStatus)
	}
	events := store.events.Snapshot()
	last := events[len(events)-1]
	if last.Type != democrypto.EventFallback {
		t.Fatalf("event = %q, want fallback", last.Type)
	}
	if last.Severity != democrypto.SeverityWarning {
		t.Fatalf("severity = %q", last.Severity)
	}
}

func TestLegacyAllowedClassical(t *testing.T) {
	baseURL, store, cleanup := startPolicyServer(t, "classical", democrypto.LegacyAllowed)
	defer cleanup()

	client := dialTLSClient(tls.X25519)
	resp, err := client.Get(baseURL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if store.status().PolicyStatus != democrypto.StatusCompliant {
		t.Fatalf("status = %q", store.status().PolicyStatus)
	}
}

func TestStatusBeforeConnection(t *testing.T) {
	_, store, cleanup := startPolicyServer(t, "hybrid", democrypto.HybridRequired)
	defer cleanup()

	st := store.status()
	if st.PolicyStatus != "no_connection" {
		t.Fatalf("policy_status = %q", st.PolicyStatus)
	}
	if st.LastNegotiatedGroup != nil {
		t.Fatalf("fabricated last_negotiated_group = %v", st.LastNegotiatedGroup)
	}
}

func TestStatusEndpoint(t *testing.T) {
	baseURL, _, cleanup := startPolicyServer(t, "hybrid", democrypto.HybridRequired)
	defer cleanup()

	client := dialTLSClient(tls.X25519MLKEM768)
	var status statusResponse
	getJSON(t, client, baseURL+"/status", &status)
	if status.Provider != "hybrid" {
		t.Fatalf("provider = %q", status.Provider)
	}
	if status.Policy != string(democrypto.HybridRequired) {
		t.Fatalf("policy = %q", status.Policy)
	}
	if status.LastNegotiatedGroup == nil || *status.LastNegotiatedGroup != "X25519MLKEM768" {
		t.Fatalf("last_negotiated_group = %v", status.LastNegotiatedGroup)
	}
	if status.PolicyStatus != democrypto.StatusCompliant {
		t.Fatalf("policy_status = %q", status.PolicyStatus)
	}
}

func TestSecurityEventsEndpoint(t *testing.T) {
	baseURL, _, cleanup := startPolicyServer(t, "hybrid", democrypto.HybridRequired)
	defer cleanup()

	client := dialTLSClient(tls.X25519MLKEM768)
	resp, err := client.Get(baseURL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	resp.Body.Close()

	var payload struct {
		Events []democrypto.SecurityEvent `json:"events"`
	}
	getJSON(t, client, baseURL+"/security-events", &payload)
	if len(payload.Events) == 0 {
		t.Fatal("/security-events returned no events")
	}
	found := false
	for _, ev := range payload.Events {
		if ev.Type == democrypto.EventCompliant && ev.NegotiatedGroup == "X25519MLKEM768" {
			found = true
			if ev.Timestamp == "" || ev.Policy == "" || ev.Message == "" {
				t.Fatalf("incomplete security event: %+v", ev)
			}
		}
	}
	if !found {
		t.Fatalf("expected CRYPTO_POLICY_COMPLIANT event; got %+v", payload.Events)
	}
}

func TestCBOMEndpointAfterHandshake(t *testing.T) {
	baseURL, _, cleanup := startPolicyServer(t, "hybrid", democrypto.HybridRequired)
	defer cleanup()

	client := dialTLSClient(tls.X25519MLKEM768)
	resp, err := client.Get(baseURL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	state := resp.TLS
	resp.Body.Close()

	var inv democrypto.CryptoInventory
	getJSON(t, client, baseURL+"/cbom", &inv)
	if inv.Provider != "hybrid" {
		t.Fatalf("provider = %q", inv.Provider)
	}
	if !inv.Negotiated.Available {
		t.Fatal("negotiated unavailable")
	}
	var haveConfigured, haveNegotiated, haveCipher bool
	for _, a := range inv.Assets {
		if a.Source == "configured" && a.Name == "X25519MLKEM768" {
			haveConfigured = true
		}
		if a.Source == "negotiated" && a.Category == "key_agreement" && a.Name == state.CurveID.String() {
			haveNegotiated = true
		}
		if a.Source == "negotiated" && a.Category == "cipher" && a.Name == tls.CipherSuiteName(state.CipherSuite) {
			haveCipher = true
		}
	}
	if !haveConfigured || !haveNegotiated || !haveCipher {
		t.Fatalf("inventory incomplete: %+v", inv.Assets)
	}
}

func TestInventoryBeforeHandshake(t *testing.T) {
	_, store, cleanup := startPolicyServer(t, "hybrid", democrypto.HybridRequired)
	defer cleanup()

	inv := store.inventory()
	if inv.Negotiated.Available {
		t.Fatal("negotiated available before handshake")
	}
	for _, a := range inv.Assets {
		if a.Source == "negotiated" {
			t.Fatalf("fabricated negotiated asset: %+v", a)
		}
	}
}

func TestLoadConfig(t *testing.T) {
	cfg, err := loadConfig("config/crypto-policy.yaml")
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Provider == "" || cfg.Policy == "" {
		t.Fatalf("incomplete config: %+v", cfg)
	}
	if _, err := democrypto.ParsePolicyMode(cfg.Policy); err != nil {
		t.Fatalf("policy: %v", err)
	}

	if _, err := loadConfig("config/does-not-exist.yaml"); err == nil {
		t.Fatal("expected missing file error")
	}
}

func TestLoadConfigValidation(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		t.Helper()
		path := dir + "/" + name
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		return path
	}

	cases := []struct {
		name string
		body string
	}{
		{"empty provider", "provider: \"\"\npolicy: HYBRID_REQUIRED\n"},
		{"empty policy", "provider: hybrid\npolicy: \"\"\n"},
		{"bad provider", "provider: quantum-magic\npolicy: HYBRID_REQUIRED\n"},
		{"bad policy", "provider: hybrid\npolicy: ALWAYS_SECURE\n"},
		{"malformed", "provider: [hybrid\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := write(tc.name+".yaml", tc.body)
			if _, err := loadConfig(path); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestClientCurvePreferences(t *testing.T) {
	hybrid, err := clientCurvePreferences("hybrid")
	if err != nil || len(hybrid) != 1 || hybrid[0] != tls.X25519MLKEM768 {
		t.Fatalf("hybrid = %v err=%v", hybrid, err)
	}
	classical, err := clientCurvePreferences("classical")
	if err != nil || len(classical) != 1 || classical[0] != tls.X25519 {
		t.Fatalf("classical = %v err=%v", classical, err)
	}
	auto, err := clientCurvePreferences("")
	if err != nil || len(auto) != 2 {
		t.Fatalf("auto = %v err=%v", auto, err)
	}
}
