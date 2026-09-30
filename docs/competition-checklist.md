# Competition Readiness Checklist

Use before presenting. Check items only after verifying on the presentation
machine.

## Functionality

- [ ] Classical TLS 1.3 works
- [ ] Hybrid TLS 1.3 works
- [ ] Provider abstraction works
- [ ] Policy configuration works
- [ ] Policy violation is detected
- [ ] `/status` works
- [ ] `/cbom` works
- [ ] `/security-events` works
- [ ] HNDL experiment works
- [ ] Benchmark works

## Correctness

- [ ] No secret material is logged
- [ ] No unsafe/reflection TLS extraction
- [ ] No fabricated negotiated cryptography
- [ ] Unknown algorithms are not silently classified
- [ ] Policy violation is not described as attack detection
- [ ] HNDL experiment is accurately described

## Testing

- [ ] `go test ./...`
- [ ] `go test -race ./...`
- [ ] Demo script succeeds (`./scripts/run-demo.sh`)
- [ ] Benchmark succeeds
- [ ] Classical configuration reproduced
- [ ] Hybrid configuration reproduced
- [ ] Intentional policy violation reproduced

## Documentation

- [ ] Architecture diagram (`docs/architecture.md`)
- [ ] Threat model (`docs/threat-model.md`)
- [ ] Evaluation methodology (`docs/evaluation.md`)
- [ ] Results (filled from `results/benchmark.json`)
- [ ] Limitations
- [ ] Reproduction instructions
- [ ] Demo script (`docs/demo-script.md`)
- [ ] README

## Scientific honesty

- [ ] No “quantum-secure TLS” marketing claim
- [ ] “CBOM-inspired” used (not CycloneDX compliance)
- [ ] Benchmark phrased as host-specific measurements
- [ ] Case C labeled policy enforcement, not attack proof

## Quality gate

```bash
gofmt -w .
go test ./...
go test -race ./...
./scripts/run-demo.sh
```
