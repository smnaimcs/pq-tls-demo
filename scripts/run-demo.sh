#!/usr/bin/env bash
# Reproducible end-to-end demonstration of pq-tls-demo.
# No Docker, Kubernetes, databases, or cloud services required.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BIN="${TMPDIR:-/tmp}/pq-tls-demo-bin-$$"
SERVER_LOG="${TMPDIR:-/tmp}/pq-tls-demo-server-$$.log"
X25519_CHECK="${TMPDIR:-/tmp}/pq-x25519mlkem768-check-$$.go"
SERVER_PID=""
RESULTS_DIR="$ROOT/results"
mkdir -p "$RESULTS_DIR"

cleanup() {
  if [[ -n "${SERVER_PID}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -f "$BIN" "$SERVER_LOG" "$X25519_CHECK"
}
trap cleanup EXIT

step() {
  printf '\n=== %s ===\n' "$1"
}

fail() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

wait_for_server() {
  local i
  for i in $(seq 1 50); do
    if grep -q "Server listening" "$SERVER_LOG" 2>/dev/null; then
      sleep 0.2
      return 0
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      echo "---- server log ----" >&2
      cat "$SERVER_LOG" >&2 || true
      fail "server exited before becoming ready"
    fi
    sleep 0.1
  done
  echo "---- server log ----" >&2
  cat "$SERVER_LOG" >&2 || true
  fail "server did not become ready in time"
}

start_server() {
  local cfg="$1"
  if [[ -n "${SERVER_PID}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
    sleep 0.3
  fi
  : >"$SERVER_LOG"
  "$BIN" server --config="$cfg" >"$SERVER_LOG" 2>&1 &
  SERVER_PID=$!
  wait_for_server
}

run_client() {
  local mode="$1"
  "$BIN" client --mode="$mode"
}

echo "=== PQ TLS Crypto-Agility Demo ==="
echo

step "0) Environment checks"
command -v go >/dev/null 2>&1 || fail "Go is not installed or not on PATH"
go version

cat >"$X25519_CHECK" <<'EOF'
package main

import (
	"crypto/tls"
	"fmt"
)

func main() {
	fmt.Println(tls.X25519MLKEM768.String())
}
EOF
CHECK_OUT="$(go run "$X25519_CHECK")"
[[ "$CHECK_OUT" == "X25519MLKEM768" ]] || fail "Go toolchain does not expose X25519MLKEM768 (got: $CHECK_OUT)"
echo "X25519MLKEM768 support: OK"

BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
go build -o "$BIN" -ldflags "-X main.Version=0.1.0 -X main.BuildTime=${BUILD_TIME}" .
"$BIN" --version

step "1) Unit and integration tests"
go test ./...

step "2) Race detector"
go test -race ./...

step "3) Classical configuration"
start_server "config/demo-classical.yaml"
echo "[1] Classical configuration"
echo "Provider: classical"
echo "Policy: LEGACY_ALLOWED"
CLASSICAL_OUT="$(run_client classical)"
echo "$CLASSICAL_OUT" | sed -n '1,40p'
echo "$CLASSICAL_OUT" | grep -q "Negotiated Group: X25519" || fail "classical demo did not negotiate X25519"
echo "$CLASSICAL_OUT" | grep -q "Policy Status: compliant" || fail "classical demo not compliant"

step "4) Hybrid configuration"
start_server "config/demo-hybrid.yaml"
echo "[2] Hybrid configuration"
echo "Provider: hybrid"
echo "Policy: HYBRID_REQUIRED"
HYBRID_OUT="$(run_client hybrid)"
echo "$HYBRID_OUT" | sed -n '1,40p'
echo "$HYBRID_OUT" | grep -q "Negotiated Group: X25519MLKEM768" || fail "hybrid demo did not negotiate X25519MLKEM768"
echo "$HYBRID_OUT" | grep -q "Policy Status: compliant" || fail "hybrid demo not compliant"

step "5) Intentional policy violation (NOT an attack)"
# Classical provider + HYBRID_REQUIRED: TLS succeeds with X25519; policy marks violation.
start_server "config/demo-violation.yaml"
echo "[3] Intentional policy violation"
echo "Provider: classical"
echo "Policy: HYBRID_REQUIRED"
echo "Client proposal: X25519"
echo "Note: this demonstrates policy enforcement, not attack detection."
VIOLATION_OUT="$(run_client classical)"
echo "$VIOLATION_OUT" | sed -n '1,80p'
echo "$VIOLATION_OUT" | grep -q "Policy Status: violation" || fail "expected Policy Status: violation"
echo "$VIOLATION_OUT" | grep -q "CRYPTO_POLICY_VIOLATION" || fail "expected CRYPTO_POLICY_VIOLATION event"

step "6) Cryptographic inventory, status, and security events"
echo "[4] Cryptographic inventory / status / security-events"
echo "$VIOLATION_OUT" | grep -q 'GET /cbom' || fail "client did not query /cbom"
echo "$VIOLATION_OUT" | grep -q 'GET /status' || fail "client did not query /status"
echo "$VIOLATION_OUT" | grep -q 'GET /security-events' || fail "client did not query /security-events"
echo "$VIOLATION_OUT" | grep -q '"negotiated"' || fail "/cbom missing negotiated object"
echo "$VIOLATION_OUT" | grep -q '"policy_status"' || fail "/status missing policy_status"

step "7) Controlled HNDL educational experiment"
"$BIN" --experiment=hndl | tee "$RESULTS_DIR/hndl-report.txt"

step "8) Benchmark"
echo "[5] Benchmark"
"$BIN" --benchmark --count=100 --warmup=20 --json | tee "$RESULTS_DIR/benchmark.json" >/dev/null
# Derive CSV from the same JSON run so artifacts stay consistent.
python3 - "$RESULTS_DIR/benchmark.json" "$RESULTS_DIR/benchmark.csv" <<'PY'
import json, sys
src, dst = sys.argv[1], sys.argv[2]
with open(src) as f:
    report = json.load(f)
rows = [report["classical"], report["hybrid"]]
cols = [
    "mode", "handshakes", "successful", "failed",
    "mean_ms", "median_ms", "p95_ms", "p99_ms",
    "min_ms", "max_ms", "total_duration_ms",
]
with open(dst, "w") as out:
    out.write(",".join(cols) + "\n")
    for r in rows:
        out.write(",".join(str(r[c]) for c in cols) + "\n")
PY
# Also print a concise human summary for the live demo.
python3 - "$RESULTS_DIR/benchmark.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
for key in ("classical", "hybrid"):
    m = r[key]
    print(f"{m['mode']}: median={m['median_ms']:.3f}ms p95={m['p95_ms']:.3f}ms p99={m['p99_ms']:.3f}ms "
          f"success={m['successful']}/{m['handshakes']} failed={m['failed']}")
print(f"relative_mean_latency (hybrid/classical): {r['relative_mean_latency']:.3f}")
PY
echo "Wrote $RESULTS_DIR/benchmark.json"
echo "Wrote $RESULTS_DIR/benchmark.csv"

step "9) Shutdown"
echo "Demo complete."
echo
echo "Story arc: Configure → Negotiate → Observe → Assess → Enforce → Measure → Reproduce"
