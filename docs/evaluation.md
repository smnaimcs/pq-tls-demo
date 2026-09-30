# Evaluation

Evaluation report for **pq-tls-demo** (Iterations 1–5). Claims are limited to
experiments actually performed in this repository.

## 1. Problem

Financial and other long-lived digital services often depend on TLS to protect
confidentiality of traffic that may remain sensitive for years. Classical key
establishment such as X25519 is widely deployed and performant, but is not
designed to resist a future cryptographically relevant quantum computer under
the harvest-now-decrypt-later (HNDL) threat model.

Migrating toward post-quantum (PQ) or hybrid key establishment is therefore
not only an algorithm swap. Operators need **crypto-agility**: the ability to
configure, negotiate, observe, assess against policy, and measure overhead —
without rewriting application business logic for each cryptographic posture.

## 2. Threat Model

See also `docs/threat-model.md`.

In scope conceptually:

- **HNDL** against classical key establishment for long-lived sensitive data
- Dependence on a single classical key-agreement group
- Migration / interoperability friction during hybrid rollout
- Configuration drift (classical negotiation under a hybrid-required policy)

Clearly separated from demonstrated attacks:

- This prototype does **not** simulate a real quantum adversary
- Policy violations are **not** proof of an active network attack
- The HNDL harness is a **controlled educational** experiment with deliberate
  secret retention outside the TLS server path

## 3. Objectives

The prototype attempts to demonstrate that a TLS service can:

1. Perform real TLS 1.3 handshakes with classical X25519 and hybrid
   X25519MLKEM768 using Go’s standard `crypto/tls`
2. Select cryptographic posture via YAML (`provider` ≠ `policy`)
3. Emit a factual CBOM-inspired inventory of configured vs negotiated crypto
4. Evaluate negotiated results against explicit policies and emit structured
   security events
5. Illustrate HNDL implications with a controlled, non-TLS-internal experiment
6. Measure handshake latency under a documented methodology

It does **not** attempt to deliver production PKI, HSMs, banking transaction
processing, or enterprise migration automation.

## 4. Architecture

```text
Configuration (YAML)
     ↓
CryptoProvider + Policy
     ↓
TLS 1.3
     ↓
ConnectionState
     ├──→ Cryptographic Inventory (/cbom)
     └──→ Policy Evaluation
              ↓
        Security Events (/security-events)
```

Benchmarking is a separate CLI mode that measures handshake timing without
mixing inventory or HNDL work into the measured path.

Details: `docs/architecture.md`.

## 5. Implementation

| Component | Implementation |
| --- | --- |
| TLS | Go `crypto/tls`, TLS 1.3 minimum |
| Classical KE | `tls.X25519` |
| Hybrid KE | `tls.X25519MLKEM768` |
| Provider abstraction | `crypto.CryptoProvider` (`classical`, `hybrid`) |
| Policy | `HYBRID_REQUIRED`, `HYBRID_PREFERRED`, `LEGACY_ALLOWED` |
| Config | YAML; missing/invalid values fail startup (no silent defaults) |
| Inventory | CBOM-**inspired** JSON; not CycloneDX schema compliance |
| Events | In-memory bounded store; no secrets logged |
| HNDL | `experiment/` package; deliberate retention; no TLS unsafe/reflection |
| Auth certs | Self-signed ECDSA P-256 for localhost (not a PQ certificate claim) |

## 6. Migration Scenario

Conceptual organizational progression (architecture mechanism only):

```text
Classical (LEGACY_ALLOWED)
    ↓
Hybrid Preferred (HYBRID_PREFERRED)
    ↓
Hybrid Required (HYBRID_REQUIRED)
```

The same HTTP application continues to serve requests. Operators change
`config/crypto-policy.yaml` (or pass `--config`) rather than rewriting handlers.
This prototype shows the **mechanism**, not a complete enterprise migration
program (no fleet orchestration, certificate lifecycle, or change management).

## 7. Experimental Methodology

### Hardware / environment (this host)

| Field | Value |
| --- | --- |
| OS | Linux 7.0.11-76070011-generic |
| Arch | amd64 (x86_64) |
| CPU | AMD Ryzen 5 PRO 7540U w/ Radeon 740M Graphics |
| Logical CPUs | 12 |
| Go version | go1.25.0 |

### Benchmark procedure

- Certificate generated once per mode; server started once per mode
- Warm-up handshakes excluded from statistics
- Each measured sample: `tls.Dial` → read connection state → close (fresh TCP+TLS)
- Modes compared under otherwise equal conditions: Classical X25519 vs Hybrid
  X25519MLKEM768
- Metrics: iterations, successful, failed, mean, median (p50), p95, p99, min,
  max, total duration
- Handshake **byte sizes are not reported** (Go `crypto/tls` does not expose
  total handshake size; this prototype does not invent them)
- Percentiles: nearest-rank on sorted ascending durations,
  `rank = ceil(p/100 * n)`

Default demo script parameters (see `scripts/run-demo.sh`):

| Parameter | Value |
| --- | --- |
| Warm-up | 20 |
| Measured handshakes | 100 |

Larger runs (e.g. `--count=1000 --warmup=100`) are supported for paper-style
measurement; do not invent numbers — re-run and record.

## 8. Results

Measured on the evaluation host by `./scripts/run-demo.sh`
(`--count=100 --warmup=20`). These are **host-specific experimental
measurements**, not universal performance factors. Source artifact:
`results/benchmark.json`.

| Metric | Classical X25519 | Hybrid X25519MLKEM768 |
| --- | ---: | ---: |
| Handshakes (measured) | 100 | 100 |
| Successful | 100 | 100 |
| Failed | 0 | 0 |
| Mean (ms) | 0.619 | 0.790 |
| Median (ms) | 0.595 | 0.705 |
| P95 (ms) | 0.859 | 1.296 |
| P99 (ms) | 1.134 | 1.391 |
| Min (ms) | 0.422 | 0.571 |
| Max (ms) | 1.676 | 2.086 |
| Total duration (ms) | 61.9 | 79.0 |

On this test machine and under the stated methodology, the measured mean
handshake duration ratio (hybrid / classical) was approximately **1.28**.
Do not generalize this factor to other hardware, Go versions, or workloads.

Re-run `./scripts/run-demo.sh` to refresh `results/` before a presentation.

## 9. Limitations

- Prototype scope on localhost
- No production CA / certificate lifecycle
- No HSM or production key management
- No full banking transaction system
- No real quantum computer or quantum cryptanalysis
- HNDL experiment is controlled and educational
- `/cbom` is CBOM-inspired, not CycloneDX-validated
- Policy enforcement ≠ attack detection / attribution
- Hybrid key establishment ≠ every TLS component is post-quantum
  (certificates remain classical ECDSA P-256 in this demo)
- Benchmark results are not universal performance conclusions
- No Kubernetes, persistent event storage, or enterprise dashboards

## 10. Reproducibility

One-command story:

```bash
./scripts/run-demo.sh
```

Individual commands:

```bash
go test ./...
go test -race ./...

go run . --version

go run . server --config=config/demo-classical.yaml
go run . client --mode=classical

go run . server --config=config/demo-hybrid.yaml
go run . client --mode=hybrid

go run . server --config=config/demo-violation.yaml
go run . client --mode=classical

go run . --experiment=hndl
go run . --benchmark --count=100 --warmup=20 --json
```

Artifacts: `results/benchmark.json`, `results/benchmark.csv`,
`results/hndl-report.txt`.
