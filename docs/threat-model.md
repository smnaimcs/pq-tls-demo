# Threat Model

Compact structured model for the **pq-tls-demo** prototype. This is an
educational / competition prototype scope, not a full enterprise threat
assessment.

## Assets

| Asset | Notes |
| --- | --- |
| Long-lived sensitive data (conceptual) | Motivation for HNDL concern in financial-style workloads |
| TLS session confidentiality | Depends on key establishment + record protection |
| Cryptographic configuration | Provider + policy YAML |
| Key establishment group | Negotiated `CurveID` (X25519 or X25519MLKEM768) |
| Cryptographic inventory | Factual configured/negotiated observations |
| Policy decision integrity | Deterministic evaluation outcome and events |

## Threats (in scope conceptually)

| Threat | Description | Demonstrated? |
| --- | --- | --- |
| Harvest-now-decrypt-later (HNDL) | Record traffic now; attack classical key establishment later | Conceptual + controlled educational experiment only |
| Unsupported / drifted configuration | Wrong provider or policy for intended posture | Detected as policy outcome / startup validation |
| Accidental classical negotiation | Classical group under a hybrid-required policy | Policy violation event (not labeled as proven attack) |
| Inventory blind spots | Unknown negotiated algorithms silently treated as classical | Mitigated: unknown → `unknown` classification |
| Configuration ambiguity | Silent defaults hide posture | Mitigated: missing/invalid config fails startup |

## Security controls demonstrated

- Hybrid TLS 1.3 key establishment via Go `X25519MLKEM768`
- Explicit separation of **provider** (what is offered) and **policy** (what is acceptable)
- Observation of negotiated `ConnectionState`
- CBOM-inspired cryptographic inventory (`configured` vs `negotiated`)
- Structured policy events (`COMPLIANT` / `FALLBACK` / `VIOLATION`)
- Handshake performance measurement under controlled methodology

## Assumptions

- Localhost laboratory setting; no hostile network path required for the demo
- Operators control YAML configuration files
- Clients used in demos are explicit about offered groups (`--mode`)
- Self-signed ECDSA P-256 certificates are for authentication demo only — **not** a PQ certificate claim

## Out of scope

- Endpoint compromise / malware
- Stolen credentials / session tokens
- CA compromise or PKI attacks
- Hardware attacks / side channels
- Implementation-level cryptanalysis of ML-KEM
- Actual cryptographically relevant quantum attacks
- Production key management, HSMs, or enterprise orchestration
- Active Internet attack attribution

## Important distinctions

| Phrase to avoid | Precise statement |
| --- | --- |
| “Attack detected” | Cryptographic **policy violation** observed |
| “Quantum-secure TLS” | TLS 1.3 using hybrid **X25519MLKEM768** key establishment |
| “CBOM compliant” | **CBOM-inspired** inventory |
| “HNDL attack reproduced” | Controlled educational secret-recovery experiment |
