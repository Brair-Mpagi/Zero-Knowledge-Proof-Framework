# Zero-Knowledge Proof Framework

A **from-first-principles** implementation of a zero-knowledge proof system in Rust. This framework demonstrates the core mathematics and cryptographic protocols behind zk-SNARKs — without being a wrapper around existing proof libraries.

[![Rust](https://img.shields.io/badge/rust-1.96%2B-orange)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

## What This Demonstrates

- **Advanced mathematics**: Abstract algebra, finite fields (mod p), elliptic curve groups
- **Cryptographic protocol design**: Sigma protocols, Fiat-Shamir heuristic, Pedersen commitments
- **Honest scoping**: We clearly document what this system does and doesn't do vs. production SNARKs
- **Full pipeline**: Circuit → R1CS → Witness → Prove → Verify — all implemented from scratch

## Quick Start

```bash
# Build the project
cargo build --workspace

# Run all tests
cargo test --workspace

# Run examples
cargo run --example discrete_log_proof
cargo run --example sudoku_proof
cargo run --example wallet_ownership_proof

# Use the CLI
cargo run -p zkp-cli -- discrete-log --secret 42
cargo run -p zkp-cli -- sudoku
cargo run -p zkp-cli -- wallet
cargo run -p zkp-cli -- bench

# Run benchmarks
cargo bench --workspace

# Launch the web visualizer
cd visualizer && npm install && npm run dev
```

## Architecture

```
Statement (e.g. "I know Sudoku solution")
          │
          ▼
   ┌────────────────┐
   │ Circuit Builder │  developer/DSL defines variables + gates
   └───────┬────────┘
           ▼
   ┌────────────────────┐
   │ Constraint Generator│  emits R1CS matrices (A, B, C)
   └───────┬────────────┘
           ▼
   ┌────────────────────┐        private inputs
   │  Witness Generator  │◄───────────────────
   └───────┬────────────┘
           ▼
   ┌────────────────┐   commitments,     ┌─────────────────┐
   │     Prover      │──challenges────►  │     Verifier      │
   │ (Fiat-Shamir    │◄──responses─────  │ (checks           │
   │  non-interactive)│                  │  Fiat-Shamir hash)│
   └────────────────┘                    └─────────────────┘
           │
           ▼
     Proof object (serialized: commitments + responses)
```

## Proof Statements

### 1. Discrete Log Knowledge (Schnorr Protocol)
**Statement**: "I know `x` such that `g^x = Y`"

Uses the canonical Schnorr Sigma protocol with Fiat-Shamir non-interactivity.

### 2. Sudoku Solution (4×4)
**Statement**: "I know a valid solution to this puzzle"

Full R1CS pipeline with constraints for:
- Given clues match the solution
- All values in {1, 2, 3, 4}
- Row, column, and box uniqueness

### 3. Wallet Ownership
**Statement**: "I own the private key for this public key"

Schnorr-signature-style proof with domain-separated wallet identity.

## How This Differs from a Real zk-SNARK

> **This section is critical for intellectual honesty.** Our framework is educational, not production-grade.

| Property | This Framework | Real zk-SNARK (e.g., Groth16) |
|---|---|---|
| **Proof size** | O(n) — grows with constraint count | O(1) — constant size (~128 bytes) |
| **Verification time** | O(n) — checks each constraint | O(1) — constant time |
| **Trusted setup** | None needed | Required (ceremony) |
| **Polynomial commitments** | Not used | KZG / IPA commitments |
| **Pairing operations** | Not used | Bilinear pairings on G1×G2 |
| **Succinctness** | Not succinct | Succinct (the S in SNARK) |
| **Soundness** | Computational (discrete log) | Computational (knowledge assumption) |
| **Zero-knowledge** | Yes (simulator exists) | Yes |
| **Completeness** | Yes | Yes |

### What We Do Well
- Correct finite field arithmetic (via arkworks)
- Proper Fiat-Shamir with domain separation (strong Fiat-Shamir)
- Real R1CS constraint systems with satisfaction checking
- Comprehensive positive AND negative tests (soundness)
- Clean separation of concerns (circuit / prover / verifier)

### What We Simplify
- No polynomial commitment scheme (no KZG)
- Proof size scales linearly with circuit size
- No trusted setup ceremony
- No recursive proof composition
- Simplified Sigma-protocol-based proof system instead of Groth16/PLONK

These simplifications are intentional and appropriate for a portfolio project that demonstrates understanding of the underlying mathematics.

## Project Structure

```
zkp-framework/
├── Cargo.toml                    # Workspace root
├── README.md                     # This file
├── docs/
│   ├── math-background.md        # Finite fields, groups, commitments
│   └── protocol-spec.md          # Formal protocol specification
├── crates/
│   ├── zkp-core/                 # Core library
│   │   └── src/
│   │       ├── field.rs          # Finite field arithmetic (BN254 scalar field)
│   │       ├── curve.rs          # Elliptic curve operations (BN254 G1)
│   │       ├── commitment.rs     # Pedersen commitments + hash
│   │       ├── transcript.rs     # Fiat-Shamir transcript
│   │       ├── sigma.rs          # Sigma protocols (Schnorr, DLEQ, Pedersen opening)
│   │       ├── circuit/          # Circuit builder + R1CS + witness
│   │       ├── prover.rs         # R1CS satisfaction prover
│   │       ├── verifier.rs       # R1CS satisfaction verifier
│   │       └── dsl/              # Circuit description language
│   ├── zkp-cli/                  # CLI tool
│   └── zkp-wasm/                 # WASM bindings for web visualizer
├── examples/
│   ├── discrete_log_proof.rs
│   ├── sudoku_proof.rs
│   └── wallet_ownership_proof.rs
├── benches/
└── visualizer/                   # Web-based proof explorer
```

## Testing Strategy

```bash
# Run all tests
cargo test --workspace

# Run with verbose output
cargo test --workspace -- --nocapture
```

### Test Categories
- **Field arithmetic**: Identities, inverse, edge cases (0, 1, p-1)
- **Commitment tests**: Binding, hiding, homomorphic properties
- **Sigma protocol tests**: Valid proofs verify, tampered proofs rejected
- **Circuit tests**: R1CS satisfaction, constraint counting
- **Proof tests**: End-to-end for all proof statements
- **Negative tests**: Wrong inputs, tampered proofs, empty witnesses

## Tech Stack

- **Language**: Rust (edition 2021)
- **Field/Curve Arithmetic**: [arkworks](https://arkworks.rs/) (`ark-ff`, `ark-ec`, `ark-bn254`)
- **Hashing**: SHA-256 (for Fiat-Shamir)
- **CLI**: clap + colored
- **Web Visualizer**: Vite + vanilla JS + D3.js
- **WASM**: wasm-bindgen + wasm-pack

## License

MIT
