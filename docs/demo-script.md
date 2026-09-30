# Live Demo Script (5–8 minutes)

Judge-facing walkthrough. Prefer `./scripts/run-demo.sh` for a rehearsed
automated path; use these talking points for a live narration.

## 0:00–1:00 — Problem

- Financial / long-lived data may remain sensitive for years.
- Classical X25519 key establishment is widely used but faces HNDL concern
  against a future cryptographically relevant quantum computer.
- Migration needs crypto-agility: configure, negotiate, observe, assess,
  enforce, measure — without rewriting business logic.

## 1:00–2:00 — Classical Mode

Show `config/demo-classical.yaml`:

```yaml
provider: classical
policy: LEGACY_ALLOWED
```

```bash
go run . server --config=config/demo-classical.yaml
go run . client --mode=classical
```

Point to:

- TLS 1.3
- Negotiated group: **X25519**
- Policy status: **compliant**

## 2:00–3:00 — Hybrid Mode

Change **only configuration**:

```yaml
provider: hybrid
policy: HYBRID_REQUIRED
```

```bash
go run . server --config=config/demo-hybrid.yaml
go run . client --mode=hybrid
```

Point to:

- Same application binary
- TLS 1.3
- Negotiated group: **X25519MLKEM768**
- Policy status: **compliant**

## 3:00–4:00 — Policy Enforcement

Use intentional misconfiguration (classical provider + hybrid-required policy).
TLS can still negotiate X25519; the **policy evaluator** marks a violation.

```bash
go run . server --config=config/demo-violation.yaml
go run . client --mode=classical
```

Narrate precisely:

```text
HYBRID_REQUIRED + negotiated X25519 = POLICY VIOLATION
```

Say aloud: this is **policy enforcement**, not proof of an active attack.

Note: a hybrid-only server that offers solely `X25519MLKEM768` will refuse a
classical-only client at the TLS layer (no shared group). The violation config
shows application-level policy assessment when classical **was** negotiated.

## 4:00–5:00 — Cryptographic Inventory

Open `/cbom` (client prints it automatically):

- Provider
- Configured key agreement
- Negotiated key agreement (only after a real connection)
- Record-layer cipher from `ConnectionState`

Call it **CBOM-inspired**, not CycloneDX-compliant.

## 5:00–6:00 — Security Events

Open `/security-events`:

- Timestamp
- Type (`CRYPTO_POLICY_VIOLATION`, etc.)
- Provider, policy, configured group, negotiated group
- Human-readable reason

No private keys or shared secrets appear.

## 6:00–7:00 — Benchmark

```bash
go run . --benchmark --count=100 --warmup=20 --json
```

Show measured **median**, **p95**, **p99** for classical vs hybrid on **this**
machine. Phrase as host-specific experimental results.

## 7:00–8:00 — Architecture

Show `docs/architecture.md` Mermaid diagram. Close with:

> Configure → Negotiate → Observe → Assess → Enforce → Measure

Optional one-liner if time remains: `go run . --experiment=hndl` and stress
what it does **not** claim (no TLS cert private-key decryption of real TLS 1.3
sessions; no quantum cryptanalysis).
