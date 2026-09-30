// pq-tls-demo — Iteration 5: crypto policy enforcement + benchmarking
//
// Extends the TLS demo with application-level crypto policy evaluation,
// structured security events, /status and /security-events endpoints,
// and controlled TLS handshake benchmarking. Prior iterations (provider,
// inventory, HNDL experiment) remain available.
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"

	"pq-tls-demo/benchmark"
	democrypto "pq-tls-demo/crypto"
	"pq-tls-demo/experiment"
)

const listenAddr = "127.0.0.1:8443"

func main() {
	log.SetFlags(0)

	args := os.Args[1:]
	if len(args) == 0 {
		printUsage()
		os.Exit(2)
	}

	if hasFlag(args, "--version") || (len(args) == 1 && args[0] == "version") {
		fmt.Print(formatVersionInfo())
		return
	}

	// Compile-time reference: if this Go toolchain lacks X25519MLKEM768,
	// the program will not build.
	_ = tls.X25519MLKEM768

	if hasFlag(args, "--benchmark") {
		if err := runBenchmark(args); err != nil {
			log.Fatalf("benchmark error: %v", err)
		}
		return
	}

	if experimentFlag, ok := parseFlagValue(args, "--experiment"); ok {
		fmt.Printf("Go version: %s\n", runtime.Version())
		if experimentFlag != "hndl" {
			fmt.Fprintf(os.Stderr, "unknown experiment %q; use hndl\n", experimentFlag)
			os.Exit(2)
		}
		if err := runHNDLExperiment(); err != nil {
			log.Fatalf("experiment error: %v", err)
		}
		return
	}

	fmt.Printf("Go version: %s\n", runtime.Version())

	switch args[0] {
	case "server":
		cfgPath := defaultPolicyPath
		if v, ok := parseFlagValue(args[1:], "--config"); ok && v != "" {
			cfgPath = v
		}
		if err := runServer(cfgPath); err != nil {
			log.Fatalf("server error: %v", err)
		}
	case "client":
		mode, _ := parseFlagValue(args[1:], "--mode")
		if err := runClient(mode); err != nil {
			log.Fatalf("client error: %v", err)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q\n", args[0])
		printUsage()
		os.Exit(2)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "usage: %s <server|client [--mode=hybrid|classical]>\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "       %s server [--config=path]\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "       %s --experiment=hndl\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "       %s --benchmark [--count=N] [--warmup=N] [--json|--csv]\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "       %s --version\n", os.Args[0])
}

func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == name || strings.HasPrefix(a, name+"=") {
			return true
		}
	}
	return false
}

func parseFlagValue(args []string, name string) (string, bool) {
	prefix := name + "="
	for i, a := range args {
		if strings.HasPrefix(a, prefix) {
			return strings.TrimPrefix(a, prefix), true
		}
		if a == name && i+1 < len(args) {
			return args[i+1], true
		}
		if a == name {
			return "", true
		}
	}
	return "", false
}

func runHNDLExperiment() error {
	result, err := experiment.RunControlledHNDL()
	if err != nil {
		return err
	}
	fmt.Print(experiment.FormatReport(result))
	return nil
}

func runBenchmark(args []string) error {
	opts := benchmark.Options{Count: 1000, Warmup: 100}
	if v, ok := parseFlagValue(args, "--count"); ok && v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return fmt.Errorf("invalid --count %q", v)
		}
		opts.Count = n
	}
	if v, ok := parseFlagValue(args, "--warmup"); ok && v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return fmt.Errorf("invalid --warmup %q", v)
		}
		opts.Warmup = n
	}

	report, err := benchmark.Run(opts)
	if err != nil {
		return err
	}

	if hasFlag(args, "--json") {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
	if hasFlag(args, "--csv") {
		fmt.Print(benchmark.FormatCSV(report))
		return nil
	}
	fmt.Print(benchmark.FormatText(report))
	return nil
}

func providerTLSConfig(cert tls.Certificate, provider democrypto.CryptoProvider) *tls.Config {
	return &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: provider.CurvePreferences(),
	}
}

func formatTLSInfo(provider democrypto.CryptoProvider, policy democrypto.CryptoPolicyMode, state *tls.ConnectionState, result democrypto.PolicyResult) string {
	return fmt.Sprintf(
		"Configured Provider: %s\nPolicy: %s\nNegotiated Group: %s\nPolicy Status: %s\nTLS Version: %s\nCipher Suite: %s",
		provider.ID(),
		policy,
		state.CurveID.String(),
		result.Status,
		tls.VersionName(state.Version),
		tls.CipherSuiteName(state.CipherSuite),
	)
}

func runServer(cfgPath string) error {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}

	provider, err := democrypto.NewProvider(cfg.Provider)
	if err != nil {
		return err
	}
	policy, err := democrypto.ParsePolicyMode(cfg.Policy)
	if err != nil {
		return err
	}

	cert, err := generateLocalhostCert()
	if err != nil {
		return fmt.Errorf("certificate: %w", err)
	}

	store := newPostureStore(provider, policy)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.Error(w, "no TLS connection state", http.StatusInternalServerError)
			return
		}
		result := store.observe(r.TLS)

		log.Println("Connection received")
		log.Println()
		log.Println(formatTLSInfo(provider, policy, r.TLS, result))

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, formatTLSInfo(provider, policy, r.TLS, result))
	})
	mux.HandleFunc("/cbom", store.handleCBOM)
	mux.HandleFunc("/status", store.handleStatus)
	mux.HandleFunc("/security-events", store.handleSecurityEvents)

	server := &http.Server{
		Addr:      listenAddr,
		Handler:   mux,
		TLSConfig: providerTLSConfig(cert, provider),
	}

	log.Printf("Crypto Provider: %s", provider.ID())
	log.Printf("Description: %s", provider.Description())
	log.Printf("Quantum Risk: %s", provider.QuantumRisk())
	log.Printf("Configured Groups: %s", democrypto.FormatCurveIDs(provider.CurvePreferences()))
	log.Printf("Crypto Policy: %s", policy)
	log.Println()
	log.Printf("Server listening on https://%s", listenAddr)
	log.Printf("Endpoints: /  /cbom  /status  /security-events\n")

	return server.ListenAndServeTLS("", "")
}

func clientCurvePreferences(mode string) ([]tls.CurveID, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "auto":
		// Deterministic dual support so one command works with either server provider.
		return []tls.CurveID{tls.X25519MLKEM768, tls.X25519}, nil
	case "hybrid":
		return []tls.CurveID{tls.X25519MLKEM768}, nil
	case "classical":
		return []tls.CurveID{tls.X25519}, nil
	default:
		return nil, fmt.Errorf("unknown client --mode %q; use hybrid, classical, or auto", mode)
	}
}

func runClient(mode string) error {
	groups, err := clientCurvePreferences(mode)
	if err != nil {
		return err
	}

	tlsCfg := &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: groups,
		// DEMONSTRATION ONLY.
		// Do not use InsecureSkipVerify in production.
		InsecureSkipVerify: true,
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}

	fmt.Printf("Client mode: %s\n", modeOrAuto(mode))
	fmt.Printf("Client groups: %s\n", democrypto.FormatCurveIDs(groups))

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

	if resp.TLS == nil {
		return fmt.Errorf("client response has no TLS connection state")
	}

	fmt.Println()
	fmt.Printf("Client-observed negotiated group: %s\n", resp.TLS.CurveID.String())
	fmt.Printf("Client-observed TLS version: %s\n", tls.VersionName(resp.TLS.Version))
	fmt.Printf("Client-observed cipher suite: %s\n", tls.CipherSuiteName(resp.TLS.CipherSuite))

	for _, path := range []string{"/cbom", "/status", "/security-events"} {
		r, err := client.Get("https://" + listenAddr + path)
		if err != nil {
			return fmt.Errorf("fetch %s: %w", path, err)
		}
		b, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		fmt.Println()
		fmt.Printf("GET %s (%s):\n", path, r.Header.Get("Content-Type"))
		fmt.Print(string(b))
	}

	return nil
}

func modeOrAuto(mode string) string {
	if strings.TrimSpace(mode) == "" {
		return "auto"
	}
	return mode
}
