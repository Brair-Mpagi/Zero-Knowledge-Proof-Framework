# Mathematical Background

This document covers the mathematical foundations used in the ZKP framework.

## 1. Finite Fields

### Definition
A finite field F_p is the set {0, 1, 2, ..., p-1} with arithmetic modulo a prime p.

**Our choice**: We use the scalar field of the BN254 curve:  
p = 21888242871839275222246405745257275088548364400416034343698204186575808495617

### Operations
- **Addition**: (a + b) mod p
- **Subtraction**: (a - b + p) mod p
- **Multiplication**: (a × b) mod p
- **Division**: a × b⁻¹ mod p (using modular inverse)
- **Inverse**: computed via the extended Euclidean algorithm or Fermat's little theorem (a⁻¹ = a^{p-2} mod p)

### Why This Matters for ZKP
All values in our proof system live in this field. Constraints are polynomial equations over F_p.
The field being prime-order ensures every nonzero element has a multiplicative inverse.

## 2. Elliptic Curve Groups

### The BN254 Curve
We use the G1 group of the BN254 (alt_bn128) curve.

Points on the curve satisfy: y² = x³ + 3 (mod q)

where q is the base field prime.

### Group Operations
- **Point Addition**: P + Q (chord-and-tangent rule)
- **Scalar Multiplication**: n · P = P + P + ... + P (n times)
- **Generator**: A fixed point G that generates the entire group

### The Discrete Log Problem
Given G and Y = n·G, it is computationally infeasible to find n.

This is the foundational hardness assumption for our proof system.

## 3. Pedersen Commitments

### Definition
Given two generators g, h where log_g(h) is unknown:

**Commit(m, r) = g^m · h^r**

where m is the message and r is random blinding.

### Properties
- **Hiding**: C reveals nothing about m (information-theoretic, since r is uniform)
- **Binding**: Cannot find (m', r') ≠ (m, r) with same commitment (computational, under discrete log)
- **Homomorphic**: Commit(m₁, r₁) · Commit(m₂, r₂) = Commit(m₁+m₂, r₁+r₂)

### Vector Pedersen Commitments
For committing to vectors: **Commit(v⃗, r) = Σ gᵢ^vᵢ · h^r**

Used to commit to witness vectors in R1CS proofs.

## 4. Sigma Protocols

### Structure (3-move interactive proof)
1. **Commit**: Prover sends commitment R
2. **Challenge**: Verifier sends random c
3. **Response**: Prover sends s

### Schnorr Protocol (Discrete Log Knowledge)

**Statement**: "I know x such that g^x = Y"

| Step | Prover | Verifier |
|------|--------|----------|
| 1 | Pick random k, send R = g^k | |
| 2 | | Send random c |
| 3 | Send s = k + c·x | |
| 4 | | Check: g^s = R · Y^c |

### Security Properties
- **Completeness**: Honest prover always convinces honest verifier
  - Proof: g^s = g^{k+cx} = g^k · g^{cx} = R · Y^c ✓
- **Special Soundness**: From two accepting transcripts with the same R but different c, c', we can extract x
  - Given (R, c, s) and (R, c', s'): x = (s - s') / (c - c')
- **Honest-Verifier Zero-Knowledge**: A simulator can produce indistinguishable transcripts without knowing x
  - Simulator: pick random s, c; compute R = g^s · Y^{-c}

## 5. Fiat-Shamir Heuristic

### Idea
Replace the verifier's random challenge with a hash of the transcript:

**c = H(statement || commitment)**

This converts an interactive proof into a non-interactive proof (NIZK).

### Strong Fiat-Shamir
We hash both the statement AND the commitment (not just the commitment).
This prevents certain attacks in multi-proof scenarios.

### Our Implementation
```
c = SHA-256(domain_separator || generator || public_key || commitment)
```

The domain separator prevents cross-protocol attacks.

## 6. R1CS (Rank-1 Constraint Systems)

### Definition
A system of constraints of the form:

**(A · z) ∘ (B · z) = (C · z)**

where:
- A, B, C are m × n matrices (m constraints, n variables)
- z is the witness vector: z = (1, public_inputs..., private_inputs..., internals...)
- ∘ denotes the Hadamard (element-wise) product

### From Computation to Constraints
Any computation can be "flattened" into a sequence of constraints of the form:
```
(linear combination of variables) × (linear combination of variables) = (linear combination of variables)
```

Example: **x³ + x + 5 = y**
```
Intermediate variable: t = x * x
Constraint 1: x * x = t
Constraint 2: t * x + x + 5 = y  →  (t + 1) * x + 5 = y
... (further flattening needed for R1CS form)
```

### Sudoku as R1CS
For a 4×4 Sudoku, we encode:
- **Range check**: (s-1)(s-2)(s-3)(s-4) = 0 for each cell
- **Uniqueness**: (sᵢ - sⱼ) × inv = 1 for each pair in row/column/box
- **Clue matching**: grid[i] × (grid[i] - solution[i]) = 0
