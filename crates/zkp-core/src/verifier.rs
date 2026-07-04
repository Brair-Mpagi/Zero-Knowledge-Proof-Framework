//! # R1CS Satisfaction Verifier
//!
//! Verifies zero-knowledge proofs that an R1CS system is satisfied.
//! The verifier checks WITHOUT knowing the private witness values.

use crate::field::FieldElement;
use crate::curve::CurvePoint;
use crate::transcript::Transcript;
use crate::circuit::r1cs::R1CS;
use crate::prover::Proof;

/// Result of proof verification.
#[derive(Clone, Debug)]
pub struct VerificationResult {
    pub valid: bool,
    pub constraint_results: Vec<ConstraintVerResult>,
    pub verification_time_ms: u64,
}

#[derive(Clone, Debug)]
pub struct ConstraintVerResult {
    pub constraint_index: usize,
    pub challenge_valid: bool,
    pub multiplication_valid: bool,
}

pub struct Verifier;

impl Verifier {
    pub fn verify(r1cs: &R1CS, proof: &Proof) -> bool {
        Self::verify_detailed(r1cs, proof).valid
    }

    pub fn verify_detailed(r1cs: &R1CS, proof: &Proof) -> VerificationResult {
        let start = std::time::Instant::now();

        if proof.constraint_proofs.len() != r1cs.num_constraints() ||
           proof.public_inputs.len() != r1cs.num_public {
            return VerificationResult {
                valid: false, constraint_results: vec![],
                verification_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        let g = CurvePoint::generator();
        let h = CurvePoint::derive_generator(b"proof-blinding-h");

        let mut transcript = Transcript::new("r1cs-satisfaction-proof-v1");
        transcript.append_point("witness_commitment", &proof.witness_commitment);
        transcript.append_u64("num_constraints", r1cs.num_constraints() as u64);

        for (i, pi) in proof.public_inputs.iter().enumerate() {
            transcript.append_scalar(&format!("public_input_{}", i), pi);
        }

        let mut constraint_results = Vec::new();
        let mut all_valid = true;

        for i in 0..r1cs.num_constraints() {
            let cp = &proof.constraint_proofs[i];

            transcript.append_point(&format!("C_a_{}", i), &cp.commitment_a);
            transcript.append_point(&format!("C_b_{}", i), &cp.commitment_b);
            transcript.append_point(&format!("C_c_{}", i), &cp.commitment_c);
            transcript.append_point(&format!("T_{}", i), &cp.sigma_commitment);

            let expected_challenge = transcript.challenge_scalar(&format!("challenge_{}", i));
            let challenge_valid = cp.challenge == expected_challenge;

            let c_sq = cp.challenge * cp.challenge;
            let lhs = g.scalar_mul(&(cp.response_a * cp.response_b))
                + h.scalar_mul(&cp.response_cross);
            let rhs = cp.sigma_commitment + cp.commitment_c.scalar_mul(&c_sq);
            let multiplication_valid = lhs == rhs;

            if !challenge_valid || !multiplication_valid {
                all_valid = false;
            }

            constraint_results.push(ConstraintVerResult {
                constraint_index: i, challenge_valid, multiplication_valid,
            });
        }

        VerificationResult {
            valid: all_valid, constraint_results,
            verification_time_ms: start.elapsed().as_millis() as u64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::{CircuitBuilder, Witness};
    use crate::prover::Prover;

    #[test]
    fn test_verify_valid_proof() {
        let mut builder = CircuitBuilder::new();
        let x = builder.alloc_private_input();
        let y = builder.alloc_public_input();
        builder.mul(x, x, y);
        let r1cs = builder.build();

        let witness = Witness::new(
            &[FieldElement::from_u64(25)],
            &[FieldElement::from_u64(5)],
            &[],
        );

        let proof = Prover::prove(&r1cs, &witness);
        assert!(Verifier::verify(&r1cs, &proof));
    }

    #[test]
    fn test_verify_tampered_public_input() {
        let mut builder = CircuitBuilder::new();
        let x = builder.alloc_private_input();
        let y = builder.alloc_public_input();
        builder.mul(x, x, y);
        let r1cs = builder.build();

        let witness = Witness::new(
            &[FieldElement::from_u64(25)],
            &[FieldElement::from_u64(5)],
            &[],
        );

        let mut proof = Prover::prove(&r1cs, &witness);
        proof.public_inputs[0] = FieldElement::from_u64(26);
        assert!(!Verifier::verify(&r1cs, &proof));
    }

    #[test]
    fn test_verify_tampered_commitment() {
        let mut builder = CircuitBuilder::new();
        let x = builder.alloc_private_input();
        let y = builder.alloc_public_input();
        builder.mul(x, x, y);
        let r1cs = builder.build();

        let witness = Witness::new(
            &[FieldElement::from_u64(25)],
            &[FieldElement::from_u64(5)],
            &[],
        );

        let mut proof = Prover::prove(&r1cs, &witness);
        proof.constraint_proofs[0].commitment_a =
            proof.constraint_proofs[0].commitment_a + CurvePoint::generator();
        assert!(!Verifier::verify(&r1cs, &proof));
    }
}
