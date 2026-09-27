# pq-tls-demo — Iteration 1: Hybrid TLS Handshake Baseline

Minimal localhost HTTPS client/server that performs a **real TLS 1.3 handshake**
using the hybrid key-exchange group **X25519MLKEM768**, with independently
verifiable evidence from Go `ConnectionState` and (optionally) Wireshark.

## Overview

**X25519MLKEM768** is a hybrid TLS 1.3 key-exchange mechanism (IANA NamedGroup /
code point `4588` / `0x11EC`). It combines classical X25519 with the ML-KEM-768
post-quantum KEM so that the shared secret remains secure if either component
holds.

This is a **key-exchange group**, not a cipher suite:

| Concept | Example | Meaning |
| --- | --- | --- |
| Key exchange group | `X25519MLKEM768` | How the handshake derives the shared secret |
| Cipher suite | `TLS_AES_128_GCM_SHA256` | Record-layer AEAD + hash after the handshake |

This demo uses only Go’s standard `crypto/tls` (no liboqs, CIRCL, CGO, or
OpenSSL). It is **localhost-only** (`127.0.0.1:8443`).

## Requirements

- Go **1.24+** (prefer **1.26+** if available)
- Linux recommended for Wireshark capture on the loopback interface

```bash
go version
```

Go 1.24+ exposes `tls.X25519MLKEM768` in the standard library. Explicit
`CurvePreferences` make the hybrid group mandatory for this experiment.
`GODEBUG=tlsmlkem=1` is **not** required.

If your Go toolchain does not provide `tls.X25519MLKEM768`, the program will
fail to build rather than silently falling back to classical X25519.

## Project layout

```text
pq-tls-demo/
├── go.mod
├── main.go              # server + client
├── cert.go              # programmatic localhost certificate
├── integration_test.go  # asserts TLS 1.3 + X25519MLKEM768
└── README.md
```

## Run

From this directory:

```bash
go mod tidy   # optional; module is already defined
```

**Terminal 1 — server:**

```bash
go run . server
```

**Terminal 2 — client:**

```bash
go run . client
```

## Integration test

```bash
go test -v .
```

The test fails if the connection negotiates classical `X25519` or any group
other than `X25519MLKEM768`, or if the TLS version is not 1.3.

## Expected output

### Server

```text
Go version: go1.26.0
Configured key exchange: X25519MLKEM768
Server listening on https://127.0.0.1:8443

Connection received
TLS Version: TLS 1.3
Cipher Suite: TLS_AES_128_GCM_SHA256
Key Exchange Group: X25519MLKEM768
SUCCESS: X25519MLKEM768 negotiated
```

The exact cipher suite may vary (for example `TLS_AES_256_GCM_SHA384`). The
invariant that must hold is:

```text
Key Exchange Group: X25519MLKEM768
```

### Client

```text
Go version: go1.26.0
Configured key exchange: X25519MLKEM768
Connected successfully

Server-reported TLS information:
TLS Version: TLS 1.3
Cipher Suite: TLS_AES_128_GCM_SHA256
Key Exchange Group: X25519MLKEM768

Client-observed negotiated group: X25519MLKEM768
Client-observed TLS information:
TLS Version: TLS 1.3
Cipher Suite: TLS_AES_128_GCM_SHA256
Key Exchange Group: X25519MLKEM768
SUCCESS: X25519MLKEM768 negotiated
```

Both sides read the group from `tls.ConnectionState.CurveID` — values are not
hard-coded in the response path beyond formatting that field.

## Wireshark verification

Do not rely only on application logs. Confirm the hybrid group on the wire:

1. Start the server: `go run . server`
2. Start Wireshark and capture the **loopback** interface (`lo` / `Loopback: lo`)
3. Optional display filter: `tcp.port == 8443`
4. Start the client: `go run . client`
5. Locate the TLS **ClientHello**
6. Expand **TLS → Handshake Protocol: Client Hello**
7. Inspect:
   - **supported_groups** — should list X25519MLKEM768
   - **key_share** — should include a share for that group
8. Identify the IANA code point:

```text
X25519MLKEM768 = 4588 = 0x11EC
```

In Wireshark this often appears as `x25519_mlkem768 (0x11ec)` or similar,
depending on dissector version.

```text
Go ConnectionState.CurveID
        +
Wireshark ClientHello (supported_groups / key_share)
        =
independent evidence of hybrid negotiation
```

## Security limitations

- Certificate verification is intentionally disabled on the client
  (`InsecureSkipVerify`) for this localhost demo. **Do not use that in
  production.**
- This is a demonstration, not a production TLS deployment.
- No attack simulation is performed.
- No quantum computer is simulated.
- No claims are made about breaking or resisting a real quantum attacker.
- Later iterations will address crypto-policy, inventory/CBOM, downgrade
  detection, and benchmarking.
