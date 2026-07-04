//! # Finite Field Arithmetic
//!
//! Wrapper over `ark_bn254::Fr` (the scalar field of the BN254 curve).
//!
//! The BN254 scalar field has prime order:
//! p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
//!
//! All arithmetic is performed modulo this prime. We use arkworks for the
//! underlying operations (modular addition, multiplication, inversion via
//! extended Euclidean algorithm) to avoid timing/correctness bugs in
//! hand-rolled implementations.

use ark_bn254::Fr;
use ark_ff::{Field, PrimeField, UniformRand, BigInteger, Zero, One};
use ark_std::test_rng;
use serde::{Serialize, Deserialize, Serializer, Deserializer};
use std::fmt;
use std::ops::{Add, Sub, Mul, Neg};

/// A finite field element in the BN254 scalar field.
///
/// This wraps `ark_bn254::Fr` and provides a clean API for ZKP operations.
/// All arithmetic is constant-time (inherited from arkworks).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FieldElement(pub(crate) Fr);

impl FieldElement {
    /// The additive identity (0).
    pub fn zero() -> Self {
        FieldElement(Fr::zero())
    }

    /// The multiplicative identity (1).
    pub fn one() -> Self {
        FieldElement(Fr::one())
    }

    /// Create a field element from a u64 value.
    pub fn from_u64(val: u64) -> Self {
        FieldElement(Fr::from(val))
    }

    /// Create a field element from a u128 value.
    pub fn from_u128(val: u128) -> Self {
        FieldElement(Fr::from(val))
    }

    /// Create a field element from a byte array (little-endian).
    /// Returns None if the bytes don't represent a valid field element.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        Fr::from_random_bytes(bytes).map(FieldElement)
    }

    /// Create a field element from a decimal string.
    pub fn from_str(s: &str) -> Option<Self> {
        s.parse::<u128>().ok().map(|v| Self::from_u128(v))
    }

    /// Generate a random field element using a cryptographically secure RNG.
    pub fn random<R: rand::Rng>(rng: &mut R) -> Self {
        FieldElement(Fr::rand(rng))
    }

    /// Generate a random field element using the test RNG (deterministic, for tests only).
    pub fn random_for_test() -> Self {
        let mut rng = test_rng();
        FieldElement(Fr::rand(&mut rng))
    }

    /// Compute the multiplicative inverse (1/self).
    /// Returns None if self is zero.
    pub fn inverse(&self) -> Option<Self> {
        self.0.inverse().map(FieldElement)
    }

    /// Compute self^exp using square-and-multiply.
    pub fn pow(&self, exp: u64) -> Self {
        FieldElement(self.0.pow([exp]))
    }

    /// Check if this element is zero.
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    /// Check if this element is one.
    pub fn is_one(&self) -> bool {
        self.0.is_one()
    }

    /// Return the negation (-self mod p).
    pub fn negate(&self) -> Self {
        FieldElement(-self.0)
    }

    /// Serialize to a 32-byte little-endian representation.
    pub fn to_bytes(&self) -> [u8; 32] {
        let bigint = self.0.into_bigint();
        let limbs = bigint.as_ref();
        let mut bytes = [0u8; 32];
        for (i, limb) in limbs.iter().enumerate() {
            let limb_bytes = limb.to_le_bytes();
            let offset = i * 8;
            for (j, b) in limb_bytes.iter().enumerate() {
                if offset + j < 32 {
                    bytes[offset + j] = *b;
                }
            }
        }
        bytes
    }

    /// Convert to a hex string for display / serialization.
    pub fn to_hex(&self) -> String {
        let bytes = self.to_bytes();
        format!("0x{}", hex::encode(bytes))
    }

    /// Convert to a decimal string (for small values / display).
    pub fn to_decimal(&self) -> String {
        format!("{}", self.0.into_bigint())
    }

    /// Access the inner arkworks Fr element.
    pub fn inner(&self) -> &Fr {
        &self.0
    }

    /// Consume and return the inner Fr.
    pub fn into_inner(self) -> Fr {
        self.0
    }
}

// === Arithmetic operator implementations ===

impl Add for FieldElement {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        FieldElement(self.0 + rhs.0)
    }
}

impl Sub for FieldElement {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        FieldElement(self.0 - rhs.0)
    }
}

impl Mul for FieldElement {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        FieldElement(self.0 * rhs.0)
    }
}

impl Neg for FieldElement {
    type Output = Self;
    fn neg(self) -> Self {
        FieldElement(-self.0)
    }
}

impl fmt::Debug for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dec = self.to_decimal();
        // Show shortened form for large numbers
        if dec.len() > 20 {
            write!(f, "F({}...{})", &dec[..8], &dec[dec.len()-8..])
        } else {
            write!(f, "F({})", dec)
        }
    }
}

impl fmt::Display for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_decimal())
    }
}

impl From<u64> for FieldElement {
    fn from(val: u64) -> Self {
        Self::from_u64(val)
    }
}

impl From<i64> for FieldElement {
    fn from(val: i64) -> Self {
        if val >= 0 {
            Self::from_u64(val as u64)
        } else {
            Self::from_u64((-val) as u64).negate()
        }
    }
}

impl From<Fr> for FieldElement {
    fn from(fr: Fr) -> Self {
        FieldElement(fr)
    }
}

// === Serde support (serialize as hex string) ===

impl Serialize for FieldElement {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for FieldElement {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let hex_str = s.strip_prefix("0x").unwrap_or(&s);
        let bytes_vec = hex::decode(hex_str).map_err(serde::de::Error::custom)?;
        if bytes_vec.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes for field element"));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&bytes_vec);
        Self::from_bytes(&bytes).ok_or_else(|| serde::de::Error::custom("invalid field element"))
    }
}

// === Hex encoding utility (inline to avoid extra dependency in wasm) ===

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        if s.len() % 2 != 0 {
            return Err("odd-length hex string".to_string());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_arithmetic() {
        let a = FieldElement::from_u64(7);
        let b = FieldElement::from_u64(11);

        assert_eq!(a + b, FieldElement::from_u64(18));
        assert_eq!(b - a, FieldElement::from_u64(4));
        assert_eq!(a * b, FieldElement::from_u64(77));
    }

    #[test]
    fn test_zero_one() {
        let zero = FieldElement::zero();
        let one = FieldElement::one();
        let a = FieldElement::from_u64(42);

        assert!(zero.is_zero());
        assert!(one.is_one());
        assert_eq!(a + zero, a);
        assert_eq!(a * one, a);
        assert_eq!(a * zero, zero);
    }

    #[test]
    fn test_inverse() {
        let a = FieldElement::from_u64(7);
        let inv = a.inverse().unwrap();
        assert_eq!(a * inv, FieldElement::one());

        // Zero has no inverse
        assert!(FieldElement::zero().inverse().is_none());
    }

    #[test]
    fn test_negation() {
        let a = FieldElement::from_u64(42);
        let neg_a = a.negate();
        assert_eq!(a + neg_a, FieldElement::zero());
    }

    #[test]
    fn test_pow() {
        let a = FieldElement::from_u64(3);
        assert_eq!(a.pow(0), FieldElement::one());
        assert_eq!(a.pow(1), a);
        assert_eq!(a.pow(2), FieldElement::from_u64(9));
        assert_eq!(a.pow(10), FieldElement::from_u64(59049));
    }

    #[test]
    fn test_serialization_roundtrip() {
        let a = FieldElement::from_u64(123456789);
        let bytes = a.to_bytes();
        let recovered = FieldElement::from_bytes(&bytes).unwrap();
        assert_eq!(a, recovered);
    }

    #[test]
    fn test_field_identities() {
        // Commutativity
        let a = FieldElement::from_u64(7);
        let b = FieldElement::from_u64(13);
        assert_eq!(a + b, b + a);
        assert_eq!(a * b, b * a);

        // Associativity
        let c = FieldElement::from_u64(19);
        assert_eq!((a + b) + c, a + (b + c));
        assert_eq!((a * b) * c, a * (b * c));

        // Distributivity
        assert_eq!(a * (b + c), a * b + a * c);
    }

    #[test]
    fn test_subtraction_underflow() {
        // In a field, subtraction wraps: 3 - 7 = p - 4
        let a = FieldElement::from_u64(3);
        let b = FieldElement::from_u64(7);
        let result = a - b;
        // result + 7 should equal 3
        assert_eq!(result + b, a);
    }

    #[test]
    fn test_from_negative() {
        let neg5 = FieldElement::from(-5i64);
        let five = FieldElement::from(5u64);
        assert_eq!(neg5 + five, FieldElement::zero());
    }
}
