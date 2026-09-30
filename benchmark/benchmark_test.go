package benchmark

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestPercentileNearestRank(t *testing.T) {
	// 1..100 ms
	ds := make([]time.Duration, 100)
	for i := 0; i < 100; i++ {
		ds[i] = time.Duration(i+1) * time.Millisecond
	}

	if got := PercentileNearestRank(ds, 50); got != 50*time.Millisecond {
		t.Fatalf("median/p50 = %v, want 50ms", got)
	}
	if got := PercentileNearestRank(ds, 95); got != 95*time.Millisecond {
		t.Fatalf("p95 = %v, want 95ms", got)
	}
	if got := PercentileNearestRank(ds, 99); got != 99*time.Millisecond {
		t.Fatalf("p99 = %v, want 99ms", got)
	}
	if got := PercentileNearestRank(ds, 100); got != 100*time.Millisecond {
		t.Fatalf("p100 = %v, want 100ms", got)
	}
	if got := PercentileNearestRank(nil, 50); got != 0 {
		t.Fatalf("empty p50 = %v, want 0", got)
	}
}

func TestMeanDuration(t *testing.T) {
	ds := []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 30 * time.Millisecond}
	if got := MeanDuration(ds); got != 20*time.Millisecond {
		t.Fatalf("mean = %v, want 20ms", got)
	}
}

func TestMeasureSmallRun(t *testing.T) {
	report, err := Run(Options{Count: 5, Warmup: 2})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Classical.Successful == 0 || report.Hybrid.Successful == 0 {
		t.Fatalf("expected successful handshakes: classical=%+v hybrid=%+v",
			report.Classical, report.Hybrid)
	}
	if report.Classical.Handshakes != 5 || report.Hybrid.Handshakes != 5 {
		t.Fatalf("handshakes count mismatch")
	}
	if report.RelativeMean <= 0 {
		t.Fatalf("relative_mean_latency = %v, want > 0", report.RelativeMean)
	}
	text := FormatText(report)
	if text == "" {
		t.Fatal("empty format text")
	}
}

func TestMeasureReportsNoHandshakeSize(t *testing.T) {
	report, err := Run(Options{Count: 3, Warmup: 1})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Environment.Warmup != 1 {
		t.Fatalf("warmup = %d, want 1 (warm-up separated from measured runs)", report.Environment.Warmup)
	}
	if report.Classical.Failed < 0 || report.Hybrid.Failed < 0 {
		t.Fatal("failed handshake counts must be non-negative")
	}

	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	lower := strings.ToLower(string(raw))
	for _, banned := range []string{"handshake_bytes", "bytes_exchanged", "handshake_size"} {
		if strings.Contains(lower, banned) {
			t.Fatalf("JSON invents handshake-size field %q: %s", banned, raw)
		}
	}
}
