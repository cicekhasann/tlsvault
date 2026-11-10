# tlsvault

Zero-trust TLS 1.3 handshake packet inspector, cipher suite auditor, and X.509 chain validator.

Analyzes raw TLS record layers, measures 1-RTT handshake latency, audits AEAD cipher suites, and inspects ALPN protocol negotiation.

```
 Client                                              Server
   |                                                   |
   | -------- ClientHello (KeyShare, ALPN, SNI) -----> |  [0-RTT / Plaintext]
   |                                                   |
   | <------- ServerHello (KeyShare selected) -------- |
   | <======= {EncryptedExtensions} ================== |  [1-RTT / Handshake Key]
   | <======= {Certificate + CertVerify} ============= |
   | <======= {Finished} ============================= |
   |                                                   |
   | =======> {Finished} ============================= |
   |                                                   |
   | <======> [Application Data (AEAD / ChaCha20)] <=> |  [Zero-Trust Secure Channel]
```

## Features

- **TLS 1.3 Audit:** Validates 1-RTT ephemeral key exchange (ECDHE Curve25519 / P-256) and rejects weak legacy ciphers (CBC, 3DES, RC4).
- **Zero-Allocation Record Parsing:** Fast decoding of 5-byte TLS record headers (Type, Version, Length).
- **Certificate Chain Health:** Computes exact days until expiry, issuer authority, and subject alternative names (SANs).
- **ALPN Inspection:** Detects negotiated multiplexing protocols (`h2`, `http/1.1`, `grpc`).

## Building & Testing

```bash
make test    # Run unit tests & local TLS 1.3 handshake verification
make race    # Run thread-safety race detector
make bench   # Run benchmark suite
make build   # Build static binary to bin/tlsvault
```

## CLI Usage

```bash
# Audit a live remote host
./bin/tlsvault audit hasancicek.dev:443

# Output structured JSON
./bin/tlsvault audit google.com:443 -json
```

## License

MIT License.
