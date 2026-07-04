//! # Sigma Protocols
//!
//! Implementation of Sigma (Σ) protocols — the canonical building block for
//! zero-knowledge proofs of knowledge.
//!
//! ## Protocols Implemented
//!
//! ### 1. Schnorr Protocol (Discrete Log Knowledge)
//! Proves: "I know `x` such that `g^x = Y`" (without revealing `x`)
//!
//! Interactive protocol:
//! 1. Prover picks random `k`, sends `R = g^k`
//! 2. Verifier sends random challenge `c`
//! 3. Prover sends `s = k + c·x`
//! 4. Verifier checks: `g^s == R · Y^c`
//!
//! Made non-interactive via Fiat-Shamir: `c = H(g || Y || R)`
//!
//! ### 2. Pedersen Opening Protocol
//! Proves: "I know `(m, r)` such that `C = g^m · h^r`"
//!
//! ### 3. DLEQ (Discrete Log Equality)
//! Proves: "I know `x` such that `A = g^x` AND `B = h^x`"
//! (i.e., the discrete log is the same in both bases)

use crate::field::FieldElement;
use crate::curve::CurvePoint;
use crate::transcript::Transcript;
use serde::{Serialize, Deserialize};

// ============================================================
// Schnorr Protocol — Proof of Discrete Log Knowledge
// ============================================================

/// A non-interactive Schnorr proof that the prover knows `x` such that `g^x = public_key`.
///
/// ## Security Properties
/// - **Completeness**: An honest prover with a valid witness always convinces the verifier.
/// - **Soundness**: A cheating prover without the witness succeeds with probability ≤ 1/|F|.
/// - **Zero-Knowledge**: The proof reveals nothing about `x` (simulatable).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SchnorrProof {
    /// The commitment: R = g^k (where k is the prover's random nonce)
    pub commitment: CurvePoint,
    /// The Fiat-Shamir challenge: c = H(g || public_key || R)
    pub challenge: FieldElement,
    /// The response: s = k + c·x
    pub response: FieldElement,
}

impl SchnorrProof {
    /// Generate a Schnorr proof that the prover knows the discrete log.
    ///
    /// Proves: "I know `secret` such that `generator^secret = public_key`"
    ///
    /// # Arguments
    /// * `generator` - The base point g
    /// * `public_key` - The public value Y = g^x
    /// * `secret` - The secret scalar x (the witness)
    pub fn prove(
        generator: &CurvePoint,
        public_key: &CurvePoint,
        secret: &FieldElement,
    ) -> Self {
        let mut rng = rand::thread_rng();

        // Step 1: Pick random nonce k, compute commitment R = g^k
        let k = FieldElement::random(&mut rng);
        let commitment = generator.scalar_mul(&k);

        // Step 2: Fiat-Shamir challenge
        let mut transcript = Transcript::new("schnorr-proof-v1");
        transcript.append_point("generator", generator);
        transcript.append_point("public_key", public_key);
        transcript.append_point("commitment", &commitment);
        let challenge = transcript.challenge_scalar("challenge");

        // Step 3: Compute response s = k + c·x
        let response = k + challenge * *secret;

        SchnorrProof {
            commitment,
            challenge,
            response,
        }
    }

    /// Verify a Schnorr proof.
    ///
    /// Checks: `g^s == R · Y^c`
    /// Equivalent to: `g^(k + c·x) == g^k · (g^x)^c`
    ///
    /// # Arguments
    /// * `generator` - The base point g
    /// * `public_key` - The claimed public value Y = g^x
    pub fn verify(&self, generator: &CurvePoint, public_key: &CurvePoint) -> bool {
        // Recompute the Fiat-Shamir challenge
        let mut transcript = Transcript::new("schnorr-proof-v1");
        transcript.append_point("generator", generator);
        transcript.append_point("public_key", public_key);
        transcript.append_point("commitment", &self.commitment);
        let expected_challenge = transcript.challenge_scalar("challenge");

        // Check challenge matches
        if self.challenge != expected_challenge {
            return false;
        }

        // Check verification equation: g^s == R + Y·c
        let lhs = generator.scalar_mul(&self.response);
        let rhs = self.commitment + public_key.scalar_mul(&self.challenge);

        lhs == rhs
    }

    /// Get the proof as a JSON string (for display/export).
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    /// Parse a proof from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

// ============================================================
// Pedersen Opening Protocol
// ============================================================

/// A proof of knowledge of the opening of a Pedersen commitment.
///
/// Proves: "I know `(m, r)` such that `C = g^m · h^r`"
///
/// This is a generalization of Schnorr to two-dimensional discrete log.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PedersenOpeningProof {
    /// Commitment: R = g^k_m · h^k_r
    pub commitment: CurvePoint,
    /// Fiat-Shamir challenge
    pub challenge: FieldElement,
    /// Response for the message: s_m = k_m + c·m
    pub response_m: FieldElement,
    /// Response for the randomness: s_r = k_r + c·r
    pub response_r: FieldElement,
}

impl PedersenOpeningProof {
    /// Generate a proof of knowledge of a Pedersen commitment opening.
    ///
    /// # Arguments
    /// * `g` - Message generator
    /// * `h` - Blinding generator
    /// * `target` - The commitment C = g^m · h^r
    /// * `message` - The committed message m
    /// * `randomness` - The blinding factor r
    pub fn prove(
        g: &CurvePoint,
        h: &CurvePoint,
        target: &CurvePoint,
        message: &FieldElement,
        randomness: &FieldElement,
    ) -> Self {
        let mut rng = rand::thread_rng();

        // Random nonces
        let k_m = FieldElement::random(&mut rng);
        let k_r = FieldElement::random(&mut rng);

        // Commitment: R = g^k_m · h^k_r
        let commitment = g.scalar_mul(&k_m) + h.scalar_mul(&k_r);

        // Fiat-Shamir challenge
        let mut transcript = Transcript::new("pedersen-opening-proof-v1");
        transcript.append_point("g", g);
        transcript.append_point("h", h);
        transcript.append_point("target", target);
        transcript.append_point("commitment", &commitment);
        let challenge = transcript.challenge_scalar("challenge");

        // Responses
        let response_m = k_m + challenge * *message;
        let response_r = k_r + challenge * *randomness;

        PedersenOpeningProof {
            commitment,
            challenge,
            response_m,
            response_r,
        }
    }

    /// Verify a Pedersen opening proof.
    ///
    /// Checks: `g^s_m · h^s_r == R · C^c`
    pub fn verify(
        &self,
        g: &CurvePoint,
        h: &CurvePoint,
        target: &CurvePoint,
    ) -> bool {
        // Recompute challenge
        let mut transcript = Transcript::new("pedersen-opening-proof-v1");
        transcript.append_point("g", g);
        transcript.append_point("h", h);
        transcript.append_point("target", target);
        transcript.append_point("commitment", &self.commitment);
        let expected_challenge = transcript.challenge_scalar("challenge");

        if self.challenge != expected_challenge {
            return false;
        }

        // Check: g^s_m · h^s_r == R + C·c
        let lhs = g.scalar_mul(&self.response_m) + h.scalar_mul(&self.response_r);
        let rhs = self.commitment + target.scalar_mul(&self.challenge);

        lhs == rhs
    }

    /// Get the proof as a JSON string.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}

// ============================================================
// DLEQ Protocol — Discrete Log Equality
// ============================================================

/// Proof that the discrete log is equal across two bases.
///
/// Proves: "I know `x` such that `A = g^x` AND `B = h^x`"
///
/// This is used in wallet ownership proofs and other scenarios where
/// you need to prove consistency across different group generators.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DleqProof {
    /// Commitment on g: R_g = g^k
    pub commitment_g: CurvePoint,
    /// Commitment on h: R_h = h^k
    pub commitment_h: CurvePoint,
    /// Fiat-Shamir challenge
    pub challenge: FieldElement,
    /// Response: s = k + c·x
    pub response: FieldElement,
}

impl DleqProof {
    /// Generate a DLEQ proof.
    ///
    /// Proves: "I know `secret` such that `A = g^secret` AND `B = h^secret`"
    pub fn prove(
        g: &CurvePoint,
        h: &CurvePoint,
        a: &CurvePoint,
        b: &CurvePoint,
        secret: &FieldElement,
    ) -> Self {
        let mut rng = rand::thread_rng();

        // Random nonce
        let k = FieldElement::random(&mut rng);

        // Commitments
        let commitment_g = g.scalar_mul(&k);
        let commitment_h = h.scalar_mul(&k);

        // Fiat-Shamir challenge
        let mut transcript = Transcript::new("dleq-proof-v1");
        transcript.append_point("g", g);
        transcript.append_point("h", h);
        transcript.append_point("A", a);
        transcript.append_point("B", b);
        transcript.append_point("R_g", &commitment_g);
        transcript.append_point("R_h", &commitment_h);
        let challenge = transcript.challenge_scalar("challenge");

        // Response
        let response = k + challenge * *secret;

        DleqProof {
            commitment_g,
            commitment_h,
            challenge,
            response,
        }
    }

    /// Verify a DLEQ proof.
    ///
    /// Checks: `g^s == R_g + A·c` AND `h^s == R_h + B·c`
    pub fn verify(
        &self,
        g: &CurvePoint,
        h: &CurvePoint,
        a: &CurvePoint,
        b: &CurvePoint,
    ) -> bool {
        // Recompute challenge
        let mut transcript = Transcript::new("dleq-proof-v1");
        transcript.append_point("g", g);
        transcript.append_point("h", h);
        transcript.append_point("A", a);
        transcript.append_point("B", b);
        transcript.append_point("R_g", &self.commitment_g);
        transcript.append_point("R_h", &self.commitment_h);
        let expected_challenge = transcript.challenge_scalar("challenge");

        if self.challenge != expected_challenge {
            return false;
        }

        // Check both equations
        let lhs_g = g.scalar_mul(&self.response);
        let rhs_g = self.commitment_g + a.scalar_mul(&self.challenge);

        let lhs_h = h.scalar_mul(&self.response);
        let rhs_h = self.commitment_h + b.scalar_mul(&self.challenge);

        lhs_g == rhs_g && lhs_h == rhs_h
    }

    /// Get the proof as a JSON string.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}

// ============================================================
// Proof Transcript (for visualization)
// ============================================================

/// A human-readable record of the proof generation process.
/// Used by the web visualizer to show step-by-step proof construction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofTranscriptStep {
    pub step_number: usize,
    pub phase: String,
    pub description: String,
    pub values: Vec<(String, String)>,
}

/// Generate a transcript of the Schnorr proof for visualization.
pub fn schnorr_proof_transcript(
    generator: &CurvePoint,
    public_key: &CurvePoint,
    proof: &SchnorrProof,
) -> Vec<ProofTranscriptStep> {
    vec![
        ProofTranscriptStep {
            step_number: 1,
            phase: "Setup".to_string(),
            description: "Public parameters and statement".to_string(),
            values: vec![
                ("Generator (g)".to_string(), format!("{:?}", generator)),
                ("Public Key (Y = g^x)".to_string(), format!("{:?}", public_key)),
                ("Statement".to_string(), "I know x such that g^x = Y".to_string()),
            ],
        },
        ProofTranscriptStep {
            step_number: 2,
            phase: "Commit".to_string(),
            description: "Prover picks random nonce k, sends R = g^k".to_string(),
            values: vec![
                ("Nonce (k)".to_string(), "[PRIVATE — redacted]".to_string()),
                ("Commitment (R)".to_string(), format!("{:?}", proof.commitment)),
            ],
        },
        ProofTranscriptStep {
            step_number: 3,
            phase: "Challenge".to_string(),
            description: "Fiat-Shamir: c = H(g || Y || R)".to_string(),
            values: vec![
                ("Challenge (c)".to_string(), format!("{:?}", proof.challenge)),
            ],
        },
        ProofTranscriptStep {
            step_number: 4,
            phase: "Response".to_string(),
            description: "Prover computes s = k + c·x".to_string(),
            values: vec![
                ("Response (s)".to_string(), format!("{:?}", proof.response)),
            ],
        },
        ProofTranscriptStep {
            step_number: 5,
            phase: "Verify".to_string(),
            description: "Verifier checks: g^s == R · Y^c".to_string(),
            values: vec![
                ("Verification".to_string(), 
                    if proof.verify(generator, public_key) { 
                        "✓ VALID".to_string() 
                    } else { 
                        "✗ INVALID".to_string() 
                    }
                ),
            ],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    // === Schnorr Protocol Tests ===

    #[test]
    fn test_schnorr_valid_proof() {
        let g = CurvePoint::generator();
        let secret = FieldElement::from_u64(42);
        let public_key = g.scalar_mul(&secret);

        let proof = SchnorrProof::prove(&g, &public_key, &secret);
        assert!(proof.verify(&g, &public_key));
    }

    #[test]
    fn test_schnorr_wrong_secret() {
        let g = CurvePoint::generator();
        let real_secret = FieldElement::from_u64(42);
        let wrong_secret = FieldElement::from_u64(43);
        let public_key = g.scalar_mul(&real_secret);

        // Prove with wrong secret
        let proof = SchnorrProof::prove(&g, &public_key, &wrong_secret);
        assert!(!proof.verify(&g, &public_key));
    }

    #[test]
    fn test_schnorr_wrong_public_key() {
        let g = CurvePoint::generator();
        let secret = FieldElement::from_u64(42);
        let public_key = g.scalar_mul(&secret);
        let wrong_pk = g.scalar_mul(&FieldElement::from_u64(99));

        let proof = SchnorrProof::prove(&g, &public_key, &secret);
        // Verify against wrong public key
        assert!(!proof.verify(&g, &wrong_pk));
    }

    #[test]
    fn test_schnorr_tampered_response() {
        let g = CurvePoint::generator();
        let secret = FieldElement::from_u64(42);
        let public_key = g.scalar_mul(&secret);

        let mut proof = SchnorrProof::prove(&g, &public_key, &secret);
        // Tamper with the response
        proof.response = proof.response + FieldElement::one();
        assert!(!proof.verify(&g, &public_key));
    }

    #[test]
    fn test_schnorr_tampered_commitment() {
        let g = CurvePoint::generator();
        let secret = FieldElement::from_u64(42);
        let public_key = g.scalar_mul(&secret);

        let mut proof = SchnorrProof::prove(&g, &public_key, &secret);
        // Tamper with the commitment
        proof.commitment = proof.commitment + g;
        assert!(!proof.verify(&g, &public_key));
    }

    #[test]
    fn test_schnorr_different_proofs_for_same_statement() {
        let g = CurvePoint::generator();
        let secret = FieldElement::from_u64(42);
        let public_key = g.scalar_mul(&secret);

        let proof1 = SchnorrProof::prove(&g, &public_key, &secret);
        let proof2 = SchnorrProof::prove(&g, &public_key, &secret);

        // Both should verify
        assert!(proof1.verify(&g, &public_key));
        assert!(proof2.verify(&g, &public_key));

        // But they should be different (different random nonces)
        assert_ne!(proof1.commitment, proof2.commitment);
    }

    #[test]
    fn test_schnorr_json_roundtrip() {
        let g = CurvePoint::generator();
        let secret = FieldElement::from_u64(42);
        let public_key = g.scalar_mul(&secret);

        let proof = SchnorrProof::prove(&g, &public_key, &secret);
        let json = proof.to_json();
        let recovered = SchnorrProof::from_json(&json).unwrap();

        assert!(recovered.verify(&g, &public_key));
    }

    // === Pedersen Opening Protocol Tests ===

    #[test]
    fn test_pedersen_opening_valid() {
        let g = CurvePoint::generator();
        let h = CurvePoint::derive_generator(b"pedersen-h");
        let msg = FieldElement::from_u64(42);
        let r = FieldElement::from_u64(999);
        let target = g.scalar_mul(&msg) + h.scalar_mul(&r);

        let proof = PedersenOpeningProof::prove(&g, &h, &target, &msg, &r);
        assert!(proof.verify(&g, &h, &target));
    }

    #[test]
    fn test_pedersen_opening_wrong_message() {
        let g = CurvePoint::generator();
        let h = CurvePoint::derive_generator(b"pedersen-h");
        let msg = FieldElement::from_u64(42);
        let wrong_msg = FieldElement::from_u64(43);
        let r = FieldElement::from_u64(999);
        let target = g.scalar_mul(&msg) + h.scalar_mul(&r);

        // Prove with wrong message
        let proof = PedersenOpeningProof::prove(&g, &h, &target, &wrong_msg, &r);
        assert!(!proof.verify(&g, &h, &target));
    }

    #[test]
    fn test_pedersen_opening_tampered() {
        let g = CurvePoint::generator();
        let h = CurvePoint::derive_generator(b"pedersen-h");
        let msg = FieldElement::from_u64(42);
        let r = FieldElement::from_u64(999);
        let target = g.scalar_mul(&msg) + h.scalar_mul(&r);

        let mut proof = PedersenOpeningProof::prove(&g, &h, &target, &msg, &r);
        proof.response_m = proof.response_m + FieldElement::one();
        assert!(!proof.verify(&g, &h, &target));
    }

    // === DLEQ Protocol Tests ===

    #[test]
    fn test_dleq_valid() {
        let g = CurvePoint::generator();
        let h = CurvePoint::derive_generator(b"dleq-h");
        let secret = FieldElement::from_u64(42);
        let a = g.scalar_mul(&secret);
        let b = h.scalar_mul(&secret);

        let proof = DleqProof::prove(&g, &h, &a, &b, &secret);
        assert!(proof.verify(&g, &h, &a, &b));
    }

    #[test]
    fn test_dleq_different_secrets() {
        let g = CurvePoint::generator();
        let h = CurvePoint::derive_generator(b"dleq-h");
        let secret1 = FieldElement::from_u64(42);
        let secret2 = FieldElement::from_u64(43);
        let a = g.scalar_mul(&secret1);
        let b = h.scalar_mul(&secret2); // Different secret!

        // Try to prove DLEQ with secret1 (but b uses secret2)
        let proof = DleqProof::prove(&g, &h, &a, &b, &secret1);
        assert!(!proof.verify(&g, &h, &a, &b));
    }

    #[test]
    fn test_dleq_tampered() {
        let g = CurvePoint::generator();
        let h = CurvePoint::derive_generator(b"dleq-h");
        let secret = FieldElement::from_u64(42);
        let a = g.scalar_mul(&secret);
        let b = h.scalar_mul(&secret);

        let mut proof = DleqProof::prove(&g, &h, &a, &b, &secret);
        proof.response = proof.response + FieldElement::one();
        assert!(!proof.verify(&g, &h, &a, &b));
    }

    // === Proof Transcript Tests ===

    #[test]
    fn test_proof_transcript_generation() {
        let g = CurvePoint::generator();
        let secret = FieldElement::from_u64(42);
        let public_key = g.scalar_mul(&secret);

        let proof = SchnorrProof::prove(&g, &public_key, &secret);
        let transcript = schnorr_proof_transcript(&g, &public_key, &proof);

        assert_eq!(transcript.len(), 5);
        assert_eq!(transcript[0].phase, "Setup");
        assert_eq!(transcript[1].phase, "Commit");
        assert_eq!(transcript[2].phase, "Challenge");
        assert_eq!(transcript[3].phase, "Response");
        assert_eq!(transcript[4].phase, "Verify");
    }
}
