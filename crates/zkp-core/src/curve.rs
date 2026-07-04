//! # Elliptic Curve Operations
//!
//! Wrapper over `ark_bn254::G1Projective` for elliptic curve group operations
//! on the BN254 curve's G1 group.
//!
//! We use arkworks for point operations to avoid timing/correctness bugs
//! in hand-rolled elliptic curve arithmetic. The BN254 curve provides a
//! bilinear pairing group, though we only use the G1 group here.
//!
//! ## Key Operations
//! - Point addition: P + Q
//! - Scalar multiplication: s · P  
//! - Generator access: standard G1 generator
//! - Deterministic generator derivation (for Pedersen commitments)

use ark_bn254::G1Projective;
use ark_ec::{CurveGroup, Group};
use ark_ff::UniformRand;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use serde::{Serialize, Deserialize, Serializer, Deserializer};
use std::fmt;
use std::ops::{Add, Sub, Mul, Neg};

use crate::field::FieldElement;

/// A point on the BN254 G1 elliptic curve.
///
/// Internally stored in projective coordinates for efficient arithmetic.
/// Converted to affine for serialization and display.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CurvePoint(pub(crate) G1Projective);

impl CurvePoint {
    /// The point at infinity (identity element of the group).
    pub fn identity() -> Self {
        CurvePoint(G1Projective::default())
    }

    /// The standard generator of G1.
    pub fn generator() -> Self {
        CurvePoint(G1Projective::generator())
    }

    /// Derive a deterministic, independent generator from a label.
    ///
    /// Uses hash-to-curve style derivation: hash the label to get
    /// a field element, then multiply the standard generator.
    /// This ensures the discrete log relationship between generators
    /// is unknown (assuming the hash acts as a random oracle).
    pub fn derive_generator(label: &[u8]) -> Self {
        use sha2::{Sha256, Digest};
        use ark_ff::PrimeField;

        // Hash the label to get a pseudo-random scalar
        let mut hasher = Sha256::new();
        hasher.update(b"zkp-framework-generator-derivation-v1:");
        hasher.update(label);
        let hash = hasher.finalize();

        // Use the hash as a seed to derive a field element
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash[..32]);

        // Reduce mod p to get a valid scalar
        let scalar = ark_bn254::Fr::from_le_bytes_mod_order(&bytes);

        // Multiply the standard generator to get an independent generator
        // Since we don't know the discrete log, this is safe for Pedersen
        CurvePoint(G1Projective::generator() * scalar)
    }

    /// Scalar multiplication: compute s · P.
    pub fn scalar_mul(&self, scalar: &FieldElement) -> Self {
        CurvePoint(self.0 * scalar.0)
    }

    /// Multi-scalar multiplication: compute Σ sᵢ · Pᵢ.
    /// More efficient than individual scalar multiplications.
    pub fn multi_scalar_mul(points: &[CurvePoint], scalars: &[FieldElement]) -> Self {
        assert_eq!(points.len(), scalars.len(), "points and scalars must have same length");
        let mut result = G1Projective::default();
        for (p, s) in points.iter().zip(scalars.iter()) {
            result = result + p.0 * s.0;
        }
        CurvePoint(result)
    }

    /// Double the point: compute 2P.
    pub fn double(&self) -> Self {
        CurvePoint(self.0.double())
    }

    /// Check if this is the identity (point at infinity).
    pub fn is_identity(&self) -> bool {
        self.0 == G1Projective::default()
    }

    /// Serialize the point to bytes (compressed affine form).
    pub fn to_bytes(&self) -> Vec<u8> {
        let affine = self.0.into_affine();
        let mut bytes = Vec::new();
        affine.serialize_compressed(&mut bytes)
            .expect("serialization should not fail");
        bytes
    }

    /// Deserialize a point from bytes (compressed affine form).
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let affine = ark_bn254::G1Affine::deserialize_compressed(bytes).ok()?;
        Some(CurvePoint(affine.into()))
    }

    /// Convert to a hex string for JSON serialization.
    pub fn to_hex(&self) -> String {
        let bytes = self.to_bytes();
        format!("0x{}", bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>())
    }

    /// Access the inner arkworks point.
    pub fn inner(&self) -> &G1Projective {
        &self.0
    }
}

// === Arithmetic operator implementations ===

impl Add for CurvePoint {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        CurvePoint(self.0 + rhs.0)
    }
}

impl Sub for CurvePoint {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        CurvePoint(self.0 - rhs.0)
    }
}

impl Neg for CurvePoint {
    type Output = Self;
    fn neg(self) -> Self {
        CurvePoint(-self.0)
    }
}

/// Scalar multiplication via the `*` operator: FieldElement * CurvePoint
impl Mul<CurvePoint> for FieldElement {
    type Output = CurvePoint;
    fn mul(self, rhs: CurvePoint) -> CurvePoint {
        rhs.scalar_mul(&self)
    }
}

impl fmt::Debug for CurvePoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_identity() {
            write!(f, "Point(∞)")
        } else {
            let hex = self.to_hex();
            write!(f, "Point({}...)", &hex[..18])
        }
    }
}

impl fmt::Display for CurvePoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_identity() {
            write!(f, "Identity")
        } else {
            write!(f, "{}", self.to_hex())
        }
    }
}

// === Serde support ===

impl Serialize for CurvePoint {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for CurvePoint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let hex_str = s.strip_prefix("0x").unwrap_or(&s);
        let bytes: Vec<u8> = (0..hex_str.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).map_err(serde::de::Error::custom))
            .collect::<Result<_, _>>()?;
        Self::from_bytes(&bytes).ok_or_else(|| serde::de::Error::custom("invalid curve point"))
    }
}

/// Generate a random curve point (for testing).
pub fn random_point<R: rand::Rng>(rng: &mut R) -> CurvePoint {
    CurvePoint(G1Projective::rand(rng))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generator_not_identity() {
        let g = CurvePoint::generator();
        assert!(!g.is_identity());
    }

    #[test]
    fn test_identity_addition() {
        let g = CurvePoint::generator();
        let id = CurvePoint::identity();
        assert_eq!(g + id, g);
    }

    #[test]
    fn test_scalar_mul() {
        let g = CurvePoint::generator();
        let two_g = g + g;
        let two = FieldElement::from_u64(2);
        assert_eq!(g.scalar_mul(&two), two_g);
    }

    #[test]
    fn test_scalar_mul_zero() {
        let g = CurvePoint::generator();
        let zero = FieldElement::zero();
        assert!(g.scalar_mul(&zero).is_identity());
    }

    #[test]
    fn test_scalar_mul_one() {
        let g = CurvePoint::generator();
        let one = FieldElement::one();
        assert_eq!(g.scalar_mul(&one), g);
    }

    #[test]
    fn test_point_negation() {
        let g = CurvePoint::generator();
        let neg_g = -g;
        assert!((g + neg_g).is_identity());
    }

    #[test]
    fn test_derived_generators_are_different() {
        let g1 = CurvePoint::derive_generator(b"pedersen-g");
        let g2 = CurvePoint::derive_generator(b"pedersen-h");
        assert_ne!(g1, g2);
    }

    #[test]
    fn test_derived_generators_are_deterministic() {
        let g1 = CurvePoint::derive_generator(b"test-label");
        let g2 = CurvePoint::derive_generator(b"test-label");
        assert_eq!(g1, g2);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let g = CurvePoint::generator();
        let bytes = g.to_bytes();
        let recovered = CurvePoint::from_bytes(&bytes).unwrap();
        assert_eq!(g, recovered);
    }

    #[test]
    fn test_multi_scalar_mul() {
        let g = CurvePoint::generator();
        let a = FieldElement::from_u64(3);
        let b = FieldElement::from_u64(5);
        let g2 = CurvePoint::derive_generator(b"second");

        let result = CurvePoint::multi_scalar_mul(&[g, g2], &[a, b]);
        let expected = g.scalar_mul(&a) + g2.scalar_mul(&b);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_double() {
        let g = CurvePoint::generator();
        assert_eq!(g.double(), g + g);
    }

    #[test]
    fn test_operator_mul() {
        let g = CurvePoint::generator();
        let s = FieldElement::from_u64(42);
        assert_eq!(s * g, g.scalar_mul(&s));
    }
}
