# pq-tls-demo

Localhost TLS 1.3 prototype exploring **crypto-agile migration** from classical
X25519 toward hybrid post-quantum key establishment (`X25519MLKEM768`), with
configuration, inventory, policy assessment, a controlled HNDL educational
experiment, and handshake benchmarking — using Go’s standard `crypto/tls`
(plus YAML for configuration).

## Problem

Services that protect long-lived sensitive data face a harvest-now-decrypt-later
(HNDL) concern if classical key establishment is later broken. Moving to hybrid
PQ key establishment is not only an algorithm change: operators must configure
posture, observe negotiation, assess policy compliance, and measure overhead
without rewriting application logic for every cryptographic mode.

## Research Question

> How can a TLS service migrate from classical X25519 toward hybrid
> post-quantum key establishment while making its cryptographic configuration,
> negotiated state, policy compliance, HNDL implications, and performance
> overhead observable?

| Concern | Iteration |
| --- | --- |
| Configuration | 2 |
| Observability / inventory | 3 |
| HNDL conceptual risk | 4 |
| Policy enforcement | 5 |
| Performance measurement | 5 |

## What We Built

Five incremental iterations on one prototype:

1. Real TLS 1.3 hybrid handshake (`X25519MLKEM768`)
2. Configuration-driven `CryptoProvider` (classical / hybrid)
3. CBOM-inspired cryptographic inventory (`/cbom`)
4. Controlled HNDL educational secret-recovery experiment
5. Crypto policy enforcement, security events, `/status`, benchmarking

## Key Contributions

- **Provider ≠ policy** — what TLS offers vs what the application accepts
- Deterministic policy matrix with structured events (not “attack detected”)
- Factual inventory separating **configured** vs **negotiated** cryptography
- Reproducible demo script and documented benchmark methodology
- Explicit scientific limitations (prototype, not production migration)

## Architecture

```text
Configuration → CryptoProvider + Policy → TLS 1.3 → ConnectionState
                     → Inventory (/cbom)
                     → Policy evaluation → Security events
Benchmark mode (separate) measures handshake latency
```

See `docs/architecture.md` for Mermaid diagrams.

## Supported Cryptographic Modes

| Provider | Offered key agreement |
| --- | --- |
| `classical` | X25519 |
| `hybrid` | X25519MLKEM768 |

Authentication certificates in this demo are self-signed **ECDSA P-256**
(localhost). That is not a post-quantum certificate claim.

## Policy Modes

| Policy | X25519MLKEM768 | X25519 |
| --- | --- | --- |
| `HYBRID_REQUIRED` | compliant | **violation** |
| `HYBRID_PREFERRED` | compliant | fallback (allowed, not preferred) |
| `LEGACY_ALLOWED` | compliant | compliant |

Classical negotiation under `HYBRID_PREFERRED` is **not** labeled an attack.

## Cryptographic Inventory

`GET /cbom` returns a **CBOM-inspired** JSON inventory (not CycloneDX schema
compliance). It includes provider, configured key agreement, and — only after a
real TLS connection — negotiated key agreement and record-layer cipher suite
from `tls.ConnectionState`. Unknown groups are classified as `unknown`, never
silently as classical.

## HNDL Educational Experiment

```bash
go run . --experiment=hndl
```

**Demonstrated:** a deliberately retained educational X25519 ephemeral secret
can reconstruct a controlled shared secret / derived key; for a hybrid
educational model (`classicalSecret + pqSecret → hybridSecret`), recovering
only the classical component is insufficient.

**Not demonstrated:** decrypting real TLS 1.3 sessions with a certificate
private key; quantum cryptanalysis; breaking ML-KEM; extracting Go’s TLS key
schedule; reproducing a passive Internet attack.

## Benchmark Methodology

```bash
go run . --benchmark --count=1000 --warmup=100
go run . --benchmark --count=100 --warmup=20 --json   # also written by demo script
```

- Warm-up excluded from statistics
- Fresh TLS connection per sample
- Reports mean, median, p95, p99, success/fail counts
- **No invented handshake byte sizes**
- Results are host-specific experimental measurements

Outputs from the demo script: `results/benchmark.json`, `results/benchmark.csv`.

## Quick Start

Requirements: Go **1.24+** (this repo targets **1.25**).

```bash
go version
go run . --version

go run . server --config=config/demo-hybrid.yaml
# other terminal:
go run . client --mode=hybrid
```

## Reproduce the Demo

```bash
./scripts/run-demo.sh
```

Deterministic scenarios:

| Case | Config | Client | Expected |
| --- | --- | --- | --- |
| A Classical | `demo-classical.yaml` | `--mode=classical` | TLS 1.3, X25519, compliant |
| B Hybrid | `demo-hybrid.yaml` | `--mode=hybrid` | TLS 1.3, X25519MLKEM768, compliant |
| C Violation | `demo-violation.yaml` | `--mode=classical` | policy **violation** (not attack proof) |

Case C uses classical provider + `HYBRID_REQUIRED` so TLS negotiates X25519 and
the evaluator emits `CRYPTO_POLICY_VIOLATION`.

## Test

```bash
gofmt -w .
go test ./...
go test -race ./...
```

## Results

See `results/` after running the demo script, and `docs/evaluation.md` §8.
Do not treat a single laptop run as a universal performance factor.

## Demonstrated vs Not Demonstrated

### Demonstrated

- TLS 1.3 with X25519 and X25519MLKEM768 via Go `crypto/tls`
- YAML-driven provider + policy (fail-closed validation)
- Inventory, status, and security-event endpoints
- Policy compliance / fallback / violation classification
- Controlled HNDL educational experiment
- Handshake latency benchmarking with documented methodology
- Reproducible one-command demo

### Not demonstrated

- Formal cryptographic proofs
- Real quantum attack simulation
- Production key / certificate management or HSMs
- Persistent security-event storage
- Full CycloneDX CBOM compliance
- Active network attack attribution
- Universal performance conclusions
- Automatic enterprise-wide migration
- Kubernetes / dashboards / production orchestration

## Limitations

This remains a **prototype**. Hybrid key establishment here does not mean every
cryptographic component is post-quantum. Policy violations are configuration /
negotiation assessments, not attack detections. See `docs/evaluation.md` §9.

## Project Structure

```text
pq-tls-demo/
├── main.go, cert.go, config.go, posture_store.go, version.go
├── integration_test.go
├── config/           # default + deterministic demo YAML
├── crypto/           # providers, inventory, policy, events
├── experiment/       # controlled HNDL harness
├── benchmark/        # handshake measurement
├── docs/             # architecture, threat model, evaluation, demo script
├── scripts/run-demo.sh
├── results/          # measured artifacts (generated)
└── README.md
```

## Documentation Index

| Doc | Purpose |
| --- | --- |
| `docs/architecture.md` | Architecture + Mermaid diagrams |
| `docs/threat-model.md` | Assets, threats, controls, out of scope |
| `docs/evaluation.md` | Evaluation report structure |
| `docs/demo-script.md` | 5–8 minute judge walkthrough |
| `docs/competition-checklist.md` | Pre-presentation checklist |

## Complete Prototype Progression

```text
Iteration 1 — Real TLS 1.3 hybrid handshake
Iteration 2 — Configuration-driven crypto provider
Iteration 3 — Cryptographic inventory / CBOM-inspired output
Iteration 4 — Controlled HNDL secret-recovery experiment
Iteration 5 — Policy enforcement + violation detection + performance measurement
```

```text
Configure → Negotiate → Observe → Assess → Enforce → Measure → Reproduce → Present
```
