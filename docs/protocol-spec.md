# Protocol Specification

Formal specification of the zero-knowledge proof protocols implemented in this framework.

## 1. System Parameters

- **Field**: F_p where p = 21888242871839275222246405745257275088548364400416034343698204186575808495617 (BN254 scalar field)
- **Group**: G1 of the BN254 curve
- **Generator**: Standard BN254 G1 generator g
- **Hash**: SHA-256 (for Fiat-Shamir transcripts)

## 2. Schnorr Protocol (NIZK)

### Public Parameters
- Generator g ∈ G1

### Statement
"I know x ∈ F_p such that g^x = Y"

### Proof Generation (Prover)
```
Input: (g, Y, x) where Y = g^x
1. k ←$ F_p                           // random nonce
2. R ← g^k                            // commitment
3. c ← H("schnorr-proof-v1" || g || Y || R)  // Fiat-Shamir challenge
4. s ← k + c·x                        // response
Output: π = (R, c, s)
```

### Verification (Verifier)
```
Input: (g, Y, π = (R, c, s))
1. c' ← H("schnorr-proof-v1" || g || Y || R)
2. Accept iff c = c' AND g^s = R · Y^c
```

### Soundness Error
ε = 1/|F_p| ≈ 2^{-254}

## 3. Pedersen Opening Protocol (NIZK)

### Public Parameters
- Generators g, h ∈ G1 (log_g(h) unknown)

### Statement
"I know (m, r) such that C = g^m · h^r"

### Proof Generation
```
Input: (g, h, C, m, r)
1. k_m, k_r ←$ F_p
2. R ← g^{k_m} · h^{k_r}
3. c ← H("pedersen-opening-v1" || g || h || C || R)
4. s_m ← k_m + c·m
5. s_r ← k_r + c·r
Output: π = (R, c, s_m, s_r)
```

### Verification
```
Input: (g, h, C, π = (R, c, s_m, s_r))
1. c' ← H("pedersen-opening-v1" || g || h || C || R)
2. Accept iff c = c' AND g^{s_m} · h^{s_r} = R · C^c
```

## 4. DLEQ Protocol (NIZK)

### Statement
"I know x such that A = g^x AND B = h^x"

### Proof Generation
```
Input: (g, h, A, B, x)
1. k ←$ F_p
2. R_g ← g^k, R_h ← h^k
3. c ← H("dleq-v1" || g || h || A || B || R_g || R_h)
4. s ← k + c·x
Output: π = (R_g, R_h, c, s)
```

### Verification
```
Accept iff c valid AND g^s = R_g · A^c AND h^s = R_h · B^c
```

## 5. R1CS Satisfaction Proof

### Public Parameters
- R1CS system: matrices (A, B, C) ∈ F^{m×n}
- Pedersen generators: g, h ∈ G1

### Statement
"I know z such that A·z ∘ B·z = C·z and z contains the claimed public inputs"

### Proof Generation (Per Constraint i)
```
For each constraint i ∈ [m]:
1. Evaluate: a_i = A_i·z, b_i = B_i·z, c_i = C_i·z
2. Commit: C_a = g^{a_i}·h^{r_a}, C_b = g^{b_i}·h^{r_b}, C_c = g^{c_i}·h^{r_c}
3. Sigma nonces: k_a, k_b, k_c, k_cross ←$ F_p
4. T = g^{k_a · k_b} · h^{k_cross}
5. c = H(transcript || C_a || C_b || C_c || T)
6. Responses: s_a = k_a + c·a_i, s_b = k_b + c·b_i, etc.
```

### Verification Equation
```
g^{s_a · s_b} · h^{s_cross} == T · C_c^{c²}
```

This checks that the committed values satisfy a_i · b_i = c_i.

### Proof Size
O(m) curve points + O(m) field elements, where m is the number of constraints.

## 6. Security Analysis

### Completeness
If the prover has a valid witness, all verification equations hold by construction.

### Soundness
An adversary without a valid witness must break either:
- The discrete log assumption (to forge Sigma protocol responses), or
- The binding property of Pedersen commitments (to open to inconsistent values)

Both reductions are tight.

### Zero-Knowledge
For each protocol, a simulator exists that produces transcripts indistinguishable from real proofs:
1. Pick random response s
2. Pick random challenge c
3. Compute commitment R from the verification equation

Since the Fiat-Shamir hash is modeled as a random oracle, the simulated transcripts are computationally indistinguishable.
