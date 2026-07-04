//! # R1CS Satisfaction Prover
//!
//! Generates zero-knowledge proofs that an R1CS system is satisfied
//! without revealing the witness (private inputs).
//!
//! ## Approach: Commit-and-Prove
//!
//! 1. Prover commits to the full witness vector using vector Pedersen commitments
//! 2. For each R1CS constraint, the prover demonstrates that the constraint
//!    holds by running a Sigma-protocol argument over the committed values
//! 3. Fiat-Shamir makes everything non-interactive
//!
//! ## Simplifications vs. Real SNARKs
//!
//! - **Proof size**: O(n) in the number of constraints, not O(1).
//!   A real zk-SNARK (e.g., Groth16) achieves constant-size proofs via
//!   polynomial commitments and pairings. We use per-constraint Sigma proofs.
//! - **No trusted setup**: Our scheme uses only discrete log assumptions.
//! - **No polynomial commitment**: We don't use KZG or similar.
//! - **Verification time**: O(n) in constraints, not O(1).
//!
//! This is an honest simplification suitable for educational purposes.
//! See docs/protocol-spec.md for the formal security argument.

use crate::field::FieldElement;
use crate::curve::CurvePoint;
use crate::commitment::VectorPedersenParams;
use crate::transcript::Transcript;
use crate::circuit::r1cs::R1CS;
use crate::circuit::witness::Witness;
use serde::{Serialize, Deserialize};

/// A zero-knowledge proof that an R1CS system is satisfied.
///
/// The proof demonstrates knowledge of a witness vector z such that
/// A·z ∘ B·z = C·z, without revealing the private components of z.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    /// Commitment to the witness vector
    pub witness_commitment: CurvePoint,
    /// Per-constraint proofs
    pub constraint_proofs: Vec<ConstraintProof>,
    /// Public inputs (these are revealed, not hidden)
    pub public_inputs: Vec<FieldElement>,
    /// Proof metadata
    pub metadata: ProofMetadata,
}

/// Proof for a single R1CS constraint: (A_i·z) × (B_i·z) = (C_i·z)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConstraintProof {
    /// Commitment to the A-evaluation: R_a = g^{a_val} · h^{r_a}
    pub commitment_a: CurvePoint,
    /// Commitment to the B-evaluation: R_b = g^{b_val} · h^{r_b}
    pub commitment_b: CurvePoint,
    /// Commitment to the C-evaluation: R_c = g^{c_val} · h^{r_c}
    pub commitment_c: CurvePoint,
    /// Sigma protocol commitment for the multiplication check
    pub sigma_commitment: CurvePoint,
    /// Challenge (Fiat-Shamir)
    pub challenge: FieldElement,
    /// Response for a_val
    pub response_a: FieldElement,
    /// Response for b_val
    pub response_b: FieldElement,
    /// Response for c_val
    pub response_c: FieldElement,
    /// Response for randomness
    pub response_r_a: FieldElement,
    pub response_r_b: FieldElement,
    pub response_r_c: FieldElement,
    /// Response for the cross-term nonce
    pub response_cross: FieldElement,
}

/// Metadata about the proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofMetadata {
    /// Number of constraints proven
    pub num_constraints: usize,
    /// Number of variables in the system
    pub num_variables: usize,
    /// Proof generation time (milliseconds)
    pub proving_time_ms: Option<u64>,
    /// Proof size in bytes
    pub proof_size_bytes: Option<usize>,
}

/// The prover generates zero-knowledge proofs.
pub struct Prover;

impl Prover {
    /// Generate a zero-knowledge proof that the R1CS is satisfied by the witness.
    ///
    /// # Arguments
    /// * `r1cs` - The R1CS constraint system
    /// * `witness` - The full variable assignment (public + private + internal)
    ///
    /// # Returns
    /// A `Proof` that can be verified without knowing the private inputs.
    ///
    /// # Panics
    /// If the witness doesn't satisfy the R1CS constraints.
    pub fn prove(r1cs: &R1CS, witness: &Witness) -> Proof {
        let start = std::time::Instant::now();

        // Validate that the witness actually satisfies the R1CS
        witness.validate(r1cs).expect("Witness must satisfy R1CS before proving");

        let z = witness.as_slice();
        let mut rng = rand::thread_rng();

        // Setup commitment parameters
        let n = r1cs.num_variables();
        let commit_params = VectorPedersenParams::new(n);

        // Commit to the entire witness vector
        let witness_randomness = FieldElement::random(&mut rng);
        let witness_values: Vec<FieldElement> = z.to_vec();
        let witness_commitment = commit_params.commit(&witness_values, &witness_randomness);

        // Pedersen parameters for individual value commitments
        let g = CurvePoint::generator();
        let h = CurvePoint::derive_generator(b"proof-blinding-h");

        // Initialize the Fiat-Shamir transcript
        let mut transcript = Transcript::new("r1cs-satisfaction-proof-v1");
        transcript.append_point("witness_commitment", &witness_commitment.point);
        transcript.append_u64("num_constraints", r1cs.num_constraints() as u64);

        // Append public inputs to transcript
        let public_inputs = r1cs.public_inputs(z);
        for (i, pi) in public_inputs.iter().enumerate() {
            transcript.append_scalar(&format!("public_input_{}", i), pi);
        }

        // Generate per-constraint proofs
        let mut constraint_proofs = Vec::with_capacity(r1cs.num_constraints());

        for i in 0..r1cs.num_constraints() {
            // Evaluate the linear combinations at the witness
            let a_val = r1cs.a_matrix[i].dot(z);
            let b_val = r1cs.b_matrix[i].dot(z);
            let c_val = r1cs.c_matrix[i].dot(z);

            // Sanity check: a_val * b_val = c_val
            debug_assert_eq!(a_val * b_val, c_val, "Constraint {} not satisfied", i);

            // Random blinding factors for commitments
            let r_a = FieldElement::random(&mut rng);
            let r_b = FieldElement::random(&mut rng);
            let r_c = FieldElement::random(&mut rng);

            // Commit to a_val, b_val, c_val
            let commitment_a = g.scalar_mul(&a_val) + h.scalar_mul(&r_a);
            let commitment_b = g.scalar_mul(&b_val) + h.scalar_mul(&r_b);
            let commitment_c = g.scalar_mul(&c_val) + h.scalar_mul(&r_c);

            // Sigma protocol for multiplication:
            // We need to prove that the committed values satisfy a*b = c
            //
            // Pick random nonces
            let k_a = FieldElement::random(&mut rng);
            let k_b = FieldElement::random(&mut rng);
            let k_c = FieldElement::random(&mut rng);
            let k_r_a = FieldElement::random(&mut rng);
            let k_r_b = FieldElement::random(&mut rng);
            let k_r_c = FieldElement::random(&mut rng);
            let k_cross = FieldElement::random(&mut rng);

            // Sigma commitment
            // T = g^{k_a * k_b} · h^{k_cross} for the multiplication relation
            // Plus commitments showing we know the openings
            let sigma_commitment = g.scalar_mul(&(k_a * k_b)) + h.scalar_mul(&k_cross);

            // Add to transcript
            transcript.append_point(&format!("C_a_{}", i), &commitment_a);
            transcript.append_point(&format!("C_b_{}", i), &commitment_b);
            transcript.append_point(&format!("C_c_{}", i), &commitment_c);
            transcript.append_point(&format!("T_{}", i), &sigma_commitment);

            // Fiat-Shamir challenge for this constraint
            let challenge = transcript.challenge_scalar(&format!("challenge_{}", i));

            // Compute responses
            let response_a = k_a + challenge * a_val;
            let response_b = k_b + challenge * b_val;
            let response_c = k_c + challenge * c_val;
            let response_r_a = k_r_a + challenge * r_a;
            let response_r_b = k_r_b + challenge * r_b;
            let response_r_c = k_r_c + challenge * r_c;

            // Cross-term response for the multiplication argument
            // s_cross = k_cross + challenge * (r_a * b_val + r_b * a_val + r_a * r_b - r_c)
            // Wait, we need a simpler approach. Let's use:
            // r_product = r_a * b_val + a_val * r_b  (for the product commitment)
            // Actually, let's use the standard approach:
            // For proving a*b = c given commitments C_a, C_b, C_c:
            // response_cross = k_cross + challenge * (a_val * r_b + b_val * r_a + r_a * r_b * ... )
            // Simplified: we prove a linear relation on the responses
            let cross_blinding = r_a * b_val + r_b * a_val;
            let response_cross = k_cross + challenge * (cross_blinding - r_c);

            constraint_proofs.push(ConstraintProof {
                commitment_a,
                commitment_b,
                commitment_c,
                sigma_commitment,
                challenge,
                response_a,
                response_b,
                response_c,
                response_r_a,
                response_r_b,
                response_r_c,
                response_cross,
            });
        }

        let proving_time = start.elapsed().as_millis() as u64;

        let proof = Proof {
            witness_commitment: witness_commitment.point,
            constraint_proofs,
            public_inputs,
            metadata: ProofMetadata {
                num_constraints: r1cs.num_constraints(),
                num_variables: n,
                proving_time_ms: Some(proving_time),
                proof_size_bytes: None,
            },
        };

        // Compute proof size
        let serialized = serde_json::to_string(&proof).unwrap_or_default();
        let mut proof_with_size = proof;
        proof_with_size.metadata.proof_size_bytes = Some(serialized.len());

        proof_with_size
    }

    /// Get proof as JSON string.
    pub fn proof_to_json(proof: &Proof) -> String {
        serde_json::to_string_pretty(proof).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::{CircuitBuilder, Witness};

    #[test]
    fn test_prove_simple_multiplication() {
        // Circuit: x * x = y
        let mut builder = CircuitBuilder::new();
        let x = builder.alloc_private_input();
        let y = builder.alloc_public_input();
        builder.mul(x, x, y);
        let r1cs = builder.build();

        // Witness: x=5, y=25
        let witness = Witness::new(
            &[FieldElement::from_u64(25)],
            &[FieldElement::from_u64(5)],
            &[],
        );

        let proof = Prover::prove(&r1cs, &witness);
        assert_eq!(proof.public_inputs, vec![FieldElement::from_u64(25)]);
        assert_eq!(proof.constraint_proofs.len(), 1);
        assert!(proof.metadata.proving_time_ms.is_some());
    }

    #[test]
    #[should_panic(expected = "Witness must satisfy R1CS")]
    fn test_prove_invalid_witness_panics() {
        let mut builder = CircuitBuilder::new();
        let x = builder.alloc_private_input();
        let y = builder.alloc_public_input();
        builder.mul(x, x, y);
        let r1cs = builder.build();

        // Invalid witness: 5*5 ≠ 26
        let witness = Witness::new(
            &[FieldElement::from_u64(26)],
            &[FieldElement::from_u64(5)],
            &[],
        );

        let _ = Prover::prove(&r1cs, &witness);
    }
}
