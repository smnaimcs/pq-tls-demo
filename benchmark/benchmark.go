package benchmark

import (
	"crypto/tls"
	"fmt"
	"math"
	"net"
	"net/http"
	"runtime"
	"sort"
	"time"
)

// Result holds measured TLS handshake statistics for one key-exchange mode.
// Handshake byte sizes are intentionally omitted: the Go TLS API does not
// expose total handshake sizes, and this prototype does not invent them.
type Result struct {
	Mode            string  `json:"mode"`
	Handshakes      int     `json:"handshakes"`
	Successful      int     `json:"successful"`
	Failed          int     `json:"failed"`
	MeanMS          float64 `json:"mean_ms"`
	MedianMS        float64 `json:"median_ms"`
	P95MS           float64 `json:"p95_ms"`
	P99MS           float64 `json:"p99_ms"`
	MinMS           float64 `json:"min_ms"`
	MaxMS           float64 `json:"max_ms"`
	TotalDurationMS float64 `json:"total_duration_ms"`
}

// Environment captures reproducibility metadata for a benchmark run.
type Environment struct {
	GoVersion  string `json:"go_version"`
	GOOS       string `json:"goos"`
	GOARCH     string `json:"goarch"`
	NumCPU     int    `json:"num_cpu"`
	Warmup     int    `json:"warmup"`
	Count      int    `json:"count"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
}

// Report is the full benchmark output for classical and hybrid modes.
type Report struct {
	Environment  Environment `json:"environment"`
	Classical    Result      `json:"classical"`
	Hybrid       Result      `json:"hybrid"`
	RelativeMean float64     `json:"relative_mean_latency"` // hybrid_mean / classical_mean
	Notes        []string    `json:"notes"`
}

// Options configures a benchmark run.
type Options struct {
	Count  int
	Warmup int
}

// PercentileNearestRank returns the nearest-rank percentile from a sorted
// ascending slice of durations. p is in (0, 100]. For an empty slice, returns 0.
//
// Method: rank = ceil(p/100 * n); value = sorted[rank-1].
func PercentileNearestRank(sorted []time.Duration, p float64) time.Duration {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[n-1]
	}
	rank := int(math.Ceil(p / 100 * float64(n)))
	if rank < 1 {
		rank = 1
	}
	if rank > n {
		rank = n
	}
	return sorted[rank-1]
}

// MeanDuration returns the arithmetic mean of durations.
func MeanDuration(ds []time.Duration) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	var sum time.Duration
	for _, d := range ds {
		sum += d
	}
	return sum / time.Duration(len(ds))
}

// Run executes warm-up then measured TLS handshakes for classical and hybrid.
func Run(opts Options) (Report, error) {
	if opts.Count <= 0 {
		opts.Count = 1000
	}
	if opts.Warmup < 0 {
		opts.Warmup = 0
	}
	if opts.Warmup == 0 && opts.Count >= 100 {
		opts.Warmup = 100
	}

	started := time.Now().UTC()
	env := Environment{
		GoVersion: runtime.Version(),
		GOOS:      runtime.GOOS,
		GOARCH:    runtime.GOARCH,
		NumCPU:    runtime.NumCPU(),
		Warmup:    opts.Warmup,
		Count:     opts.Count,
		StartedAt: started.Format(time.RFC3339),
	}

	classical, err := measureMode("Classical X25519", []tls.CurveID{tls.X25519}, opts)
	if err != nil {
		return Report{}, err
	}
	hybrid, err := measureMode("Hybrid X25519MLKEM768", []tls.CurveID{tls.X25519MLKEM768}, opts)
	if err != nil {
		return Report{}, err
	}

	env.FinishedAt = time.Now().UTC().Format(time.RFC3339)

	rel := 0.0
	if classical.MeanMS > 0 {
		rel = hybrid.MeanMS / classical.MeanMS
	}

	return Report{
		Environment:  env,
		Classical:    classical,
		Hybrid:       hybrid,
		RelativeMean: rel,
		Notes: []string{
			"Results are experimental measurements on this host; not universal performance factors.",
			"Results depend on CPU, Go version, OS, network stack, system load, and workload.",
			"Handshake byte sizes are not reported: Go crypto/tls does not expose total handshake sizes.",
			"Warm-up handshakes are excluded from reported statistics.",
		},
	}, nil
}

func measureMode(name string, groups []tls.CurveID, opts Options) (Result, error) {
	cert, err := generateCert()
	if err != nil {
		return Result{}, err
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return Result{}, err
	}
	defer ln.Close()

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
		TLSConfig: &tls.Config{
			Certificates:     []tls.Certificate{cert},
			MinVersion:       tls.VersionTLS13,
			CurvePreferences: groups,
		},
	}
	go func() { _ = server.ServeTLS(ln, "", "") }()
	defer server.Close()

	addr := ln.Addr().String()
	time.Sleep(20 * time.Millisecond)

	// Warm-up (not recorded).
	for i := 0; i < opts.Warmup; i++ {
		_, _ = oneHandshake(addr, groups)
	}

	durations := make([]time.Duration, 0, opts.Count)
	success, failed := 0, 0
	wallStart := time.Now()
	for i := 0; i < opts.Count; i++ {
		d, err := oneHandshake(addr, groups)
		if err != nil {
			failed++
			continue
		}
		success++
		durations = append(durations, d)
	}
	wall := time.Since(wallStart)

	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })

	res := Result{
		Mode:            name,
		Handshakes:      opts.Count,
		Successful:      success,
		Failed:          failed,
		TotalDurationMS: float64(wall) / float64(time.Millisecond),
	}
	if len(durations) > 0 {
		res.MeanMS = float64(MeanDuration(durations)) / float64(time.Millisecond)
		res.MedianMS = float64(PercentileNearestRank(durations, 50)) / float64(time.Millisecond)
		res.P95MS = float64(PercentileNearestRank(durations, 95)) / float64(time.Millisecond)
		res.P99MS = float64(PercentileNearestRank(durations, 99)) / float64(time.Millisecond)
		res.MinMS = float64(durations[0]) / float64(time.Millisecond)
		res.MaxMS = float64(durations[len(durations)-1]) / float64(time.Millisecond)
	}
	return res, nil
}

func oneHandshake(addr string, groups []tls.CurveID) (time.Duration, error) {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		CurvePreferences:   groups,
		InsecureSkipVerify: true, // DEMONSTRATION ONLY
		ServerName:         "localhost",
	}

	start := time.Now()
	conn, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		return 0, err
	}
	// Handshake completes in Dial for client; ensure state is available.
	state := conn.ConnectionState()
	_ = state
	_ = conn.Close()
	return time.Since(start), nil
}

// FormatText renders a human-readable benchmark table.
func FormatText(r Report) string {
	var b []byte
	w := func(format string, args ...any) {
		b = append(b, fmt.Sprintf(format, args...)...)
	}

	w("TLS Handshake Benchmark\n")
	w("=======================\n\n")
	w("Go version: %s\n", r.Environment.GoVersion)
	w("OS/Arch: %s/%s\n", r.Environment.GOOS, r.Environment.GOARCH)
	w("NumCPU: %d\n", r.Environment.NumCPU)
	w("Warm-up: %d  Measured: %d\n", r.Environment.Warmup, r.Environment.Count)
	w("Started: %s\nFinished: %s\n\n", r.Environment.StartedAt, r.Environment.FinishedAt)

	writeResult := func(res Result) {
		w("Mode: %s\n", res.Mode)
		w("Handshakes: %d\n", res.Handshakes)
		w("Successful: %d\n", res.Successful)
		w("Failed: %d\n\n", res.Failed)
		w("Mean:   %.3f ms\n", res.MeanMS)
		w("Median: %.3f ms\n", res.MedianMS)
		w("P95:    %.3f ms\n", res.P95MS)
		w("P99:    %.3f ms\n", res.P99MS)
		w("Min:    %.3f ms\n", res.MinMS)
		w("Max:    %.3f ms\n\n", res.MaxMS)
	}

	writeResult(r.Classical)
	writeResult(r.Hybrid)
	w("Relative mean latency (hybrid/classical): %.3f\n\n", r.RelativeMean)
	w("Notes:\n")
	for _, n := range r.Notes {
		w("- %s\n", n)
	}
	return string(b)
}

// FormatCSV renders classical and hybrid results as CSV rows.
func FormatCSV(r Report) string {
	var b []byte
	w := func(format string, args ...any) {
		b = append(b, fmt.Sprintf(format, args...)...)
	}
	w("mode,handshakes,successful,failed,mean_ms,median_ms,p95_ms,p99_ms,min_ms,max_ms,total_duration_ms\n")
	write := func(res Result) {
		w("%s,%d,%d,%d,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f\n",
			res.Mode, res.Handshakes, res.Successful, res.Failed,
			res.MeanMS, res.MedianMS, res.P95MS, res.P99MS, res.MinMS, res.MaxMS, res.TotalDurationMS)
	}
	write(r.Classical)
	write(r.Hybrid)
	return string(b)
}
