//! # Pedersen Commitment Scheme
//!
//! Implements Pedersen commitments: `Commit(m, r) = g^m · h^r`
//!
//! ## Properties
//! - **Hiding**: The commitment reveals nothing about `m` (information-theoretically,
//!   since `r` is uniformly random)
//! - **Binding**: The committer cannot open to a different value (computationally,
//!   under the discrete log assumption)
//! - **Homomorphic**: `Commit(m₁, r₁) · Commit(m₂, r₂) = Commit(m₁+m₂, r₁+r₂)`
//!
//! ## Vector Pedersen Commitments
//! For committing to vectors: `Commit(v⃗, r) = Σ gᵢ^vᵢ · h^r`
//! Used to commit to witness vectors in the R1CS proof system.
//!
//! ## Pedersen Hash
//! A collision-resistant hash function: `H(m₁, ..., mₙ) = Σ gᵢ^mᵢ`
//! Algebraically friendly — can be efficiently verified inside an arithmetic circuit.

use crate::field::FieldElement;
use crate::curve::CurvePoint;
use serde::{Serialize, Deserialize};

/// Parameters for the Pedersen commitment scheme.
///
/// Contains two independent generators `g` and `h` where the discrete log
/// `log_g(h)` is unknown. This is achieved by deriving `h` from a hash
/// of a fixed label (nothing-up-my-sleeve construction).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PedersenParams {
    /// Primary generator
    pub g: CurvePoint,
    /// Blinding generator (discrete log relationship to `g` is unknown)
    pub h: CurvePoint,
}

impl PedersenParams {
    /// Create Pedersen parameters with standard generators.
    ///
    /// `g` is the BN254 G1 standard generator.
    /// `h` is derived via hash-to-curve from a fixed label, ensuring
    /// the discrete log relationship is unknown.
    pub fn new() -> Self {
        PedersenParams {
            g: CurvePoint::generator(),
            h: CurvePoint::derive_generator(b"pedersen-blinding-generator-h"),
        }
    }

    /// Create Pedersen parameters with custom generators.
    pub fn with_generators(g: CurvePoint, h: CurvePoint) -> Self {
        PedersenParams { g, h }
    }

    /// Commit to a value: `C = g^m · h^r`
    pub fn commit(&self, message: &FieldElement, randomness: &FieldElement) -> PedersenCommitment {
        let point = self.g.scalar_mul(message) + self.h.scalar_mul(randomness);
        PedersenCommitment {
            point,
            // Store for verification (in a real system, the prover keeps these secret)
        }
    }

    /// Verify that a commitment opens to the claimed value.
    pub fn verify_opening(
        &self,
        commitment: &PedersenCommitment,
        message: &FieldElement,
        randomness: &FieldElement,
    ) -> bool {
        let expected = self.g.scalar_mul(message) + self.h.scalar_mul(randomness);
        commitment.point == expected
    }
}

impl Default for PedersenParams {
    fn default() -> Self {
        Self::new()
    }
}

/// A Pedersen commitment to a single field element.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PedersenCommitment {
    /// The commitment point: C = g^m · h^r
    pub point: CurvePoint,
}

impl PedersenCommitment {
    /// Create a commitment from a raw curve point.
    pub fn from_point(point: CurvePoint) -> Self {
        PedersenCommitment { point }
    }
}

// === Vector Pedersen Commitments ===

/// Parameters for vector Pedersen commitments.
///
/// Uses `n` independent generators `g₁, ..., gₙ` plus a blinding generator `h`.
/// `Commit(v⃗, r) = Σ gᵢ^vᵢ · h^r`
#[derive(Clone, Debug)]
pub struct VectorPedersenParams {
    /// Independent generators for each vector position
    pub generators: Vec<CurvePoint>,
    /// Blinding generator
    pub h: CurvePoint,
}

impl VectorPedersenParams {
    /// Create vector Pedersen parameters for vectors of length `n`.
    ///
    /// Each generator is derived deterministically from a unique label.
    pub fn new(n: usize) -> Self {
        let generators: Vec<CurvePoint> = (0..n)
            .map(|i| {
                let label = format!("pedersen-vector-generator-{}", i);
                CurvePoint::derive_generator(label.as_bytes())
            })
            .collect();

        VectorPedersenParams {
            generators,
            h: CurvePoint::derive_generator(b"pedersen-vector-blinding-h"),
        }
    }

    /// Commit to a vector: `C = Σ gᵢ^vᵢ · h^r`
    pub fn commit(&self, values: &[FieldElement], randomness: &FieldElement) -> PedersenCommitment {
        assert_eq!(
            values.len(),
            self.generators.len(),
            "vector length must match number of generators"
        );

        let mut point = self.h.scalar_mul(randomness);
        for (gi, vi) in self.generators.iter().zip(values.iter()) {
            point = point + gi.scalar_mul(vi);
        }

        PedersenCommitment { point }
    }

    /// Verify that a vector commitment opens to the claimed values.
    pub fn verify_opening(
        &self,
        commitment: &PedersenCommitment,
        values: &[FieldElement],
        randomness: &FieldElement,
    ) -> bool {
        let expected = self.commit(values, randomness);
        commitment.point == expected.point
    }
}

// === Pedersen Hash ===

/// Pedersen hash function parameters.
///
/// `H(m₁, ..., mₙ) = Σ gᵢ^mᵢ`
///
/// This is a collision-resistant hash function under the discrete log assumption.
/// Unlike SHA-256, it's algebraically friendly — a Pedersen hash can be verified
/// inside an arithmetic circuit with very few constraints.
#[derive(Clone, Debug)]
pub struct PedersenHash {
    /// Generators for each input position
    pub generators: Vec<CurvePoint>,
}

impl PedersenHash {
    /// Create a Pedersen hash function for inputs of length `n`.
    pub fn new(n: usize) -> Self {
        let generators: Vec<CurvePoint> = (0..n)
            .map(|i| {
                let label = format!("pedersen-hash-generator-{}", i);
                CurvePoint::derive_generator(label.as_bytes())
            })
            .collect();

        PedersenHash { generators }
    }

    /// Compute the Pedersen hash of a vector of field elements.
    ///
    /// `H(m₁, ..., mₙ) = Σ gᵢ^mᵢ`
    pub fn hash(&self, inputs: &[FieldElement]) -> CurvePoint {
        assert_eq!(
            inputs.len(),
            self.generators.len(),
            "input length must match number of generators"
        );

        CurvePoint::multi_scalar_mul(&self.generators, inputs)
    }

    /// Hash a single field element (convenience method).
    pub fn hash_single(&self, input: &FieldElement) -> CurvePoint {
        assert_eq!(self.generators.len(), 1, "single hash requires 1 generator");
        self.generators[0].scalar_mul(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commit_and_verify() {
        let params = PedersenParams::new();
        let msg = FieldElement::from_u64(42);
        let r = FieldElement::from_u64(12345);

        let commitment = params.commit(&msg, &r);
        assert!(params.verify_opening(&commitment, &msg, &r));
    }

    #[test]
    fn test_binding_property() {
        // Cannot open the same commitment to a different message
        let params = PedersenParams::new();
        let msg1 = FieldElement::from_u64(42);
        let msg2 = FieldElement::from_u64(43);
        let r = FieldElement::from_u64(12345);

        let commitment = params.commit(&msg1, &r);
        assert!(!params.verify_opening(&commitment, &msg2, &r));
    }

    #[test]
    fn test_different_randomness_different_commitments() {
        // Same message with different randomness produces different commitments
        let params = PedersenParams::new();
        let msg = FieldElement::from_u64(42);
        let r1 = FieldElement::from_u64(111);
        let r2 = FieldElement::from_u64(222);

        let c1 = params.commit(&msg, &r1);
        let c2 = params.commit(&msg, &r2);
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_homomorphic_property() {
        // Commit(m1, r1) + Commit(m2, r2) = Commit(m1+m2, r1+r2)
        let params = PedersenParams::new();
        let m1 = FieldElement::from_u64(10);
        let m2 = FieldElement::from_u64(20);
        let r1 = FieldElement::from_u64(100);
        let r2 = FieldElement::from_u64(200);

        let c1 = params.commit(&m1, &r1);
        let c2 = params.commit(&m2, &r2);
        let c_sum = PedersenCommitment::from_point(c1.point + c2.point);

        let m_sum = m1 + m2;
        let r_sum = r1 + r2;
        let c_direct = params.commit(&m_sum, &r_sum);

        assert_eq!(c_sum, c_direct);
    }

    #[test]
    fn test_vector_commitment() {
        let params = VectorPedersenParams::new(3);
        let values = vec![
            FieldElement::from_u64(1),
            FieldElement::from_u64(2),
            FieldElement::from_u64(3),
        ];
        let r = FieldElement::from_u64(999);

        let commitment = params.commit(&values, &r);
        assert!(params.verify_opening(&commitment, &values, &r));
    }

    #[test]
    fn test_vector_commitment_binding() {
        let params = VectorPedersenParams::new(2);
        let v1 = vec![FieldElement::from_u64(1), FieldElement::from_u64(2)];
        let v2 = vec![FieldElement::from_u64(1), FieldElement::from_u64(3)];
        let r = FieldElement::from_u64(999);

        let commitment = params.commit(&v1, &r);
        assert!(!params.verify_opening(&commitment, &v2, &r));
    }

    #[test]
    fn test_pedersen_hash_deterministic() {
        let hash = PedersenHash::new(2);
        let inputs = vec![FieldElement::from_u64(42), FieldElement::from_u64(7)];

        let h1 = hash.hash(&inputs);
        let h2 = hash.hash(&inputs);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_pedersen_hash_collision_resistance() {
        let hash = PedersenHash::new(2);
        let inputs1 = vec![FieldElement::from_u64(1), FieldElement::from_u64(2)];
        let inputs2 = vec![FieldElement::from_u64(2), FieldElement::from_u64(1)];

        assert_ne!(hash.hash(&inputs1), hash.hash(&inputs2));
    }
}
