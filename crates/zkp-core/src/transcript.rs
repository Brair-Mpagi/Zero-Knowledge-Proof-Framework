//! # Fiat-Shamir Transcript
//!
//! Implements the Fiat-Shamir heuristic for converting interactive Sigma protocols
//! into non-interactive proofs.
//!
//! ## How It Works
//!
//! In an interactive Sigma protocol:
//! 1. Prover sends commitment
//! 2. Verifier sends random challenge
//! 3. Prover sends response
//!
//! The Fiat-Shamir transform replaces step 2 by having the prover compute:
//! `challenge = H(domain_separator || public_statement || commitment)`
//!
//! This uses the random oracle model — the hash function acts as if it were
//! a truly random function, so the challenge is unpredictable to the prover.
//!
//! ## Security
//! - **Strong Fiat-Shamir**: We hash BOTH the commitment AND the public statement,
//!   not just the commitment. This prevents certain attacks in multi-proof scenarios.
//! - **Domain separation**: Each protocol use gets a unique label to prevent
//!   cross-protocol attacks.

use sha2::{Sha256, Digest};
use ark_ff::PrimeField;
use crate::field::FieldElement;
use crate::curve::CurvePoint;

/// A Fiat-Shamir transcript that accumulates protocol messages and produces
/// challenge scalars via hashing.
///
/// The transcript uses SHA-256 as the underlying hash function and maintains
/// a running state that absorbs all protocol messages.
#[derive(Clone)]
pub struct Transcript {
    hasher: Sha256,
    /// Human-readable label for debugging
    label: String,
}

impl Transcript {
    /// Create a new transcript with a domain separation label.
    ///
    /// The label should uniquely identify the protocol being used.
    /// Examples: "schnorr-proof", "pedersen-opening", "r1cs-satisfaction"
    pub fn new(label: &str) -> Self {
        let mut hasher = Sha256::new();
        // Domain separation: include the label and its length
        hasher.update(b"zkp-framework-transcript-v1:");
        hasher.update((label.len() as u32).to_le_bytes());
        hasher.update(label.as_bytes());

        Transcript {
            hasher,
            label: label.to_string(),
        }
    }

    /// Append a labeled message to the transcript.
    pub fn append_message(&mut self, label: &str, message: &[u8]) {
        self.hasher.update(b"msg:");
        self.hasher.update((label.len() as u32).to_le_bytes());
        self.hasher.update(label.as_bytes());
        self.hasher.update((message.len() as u32).to_le_bytes());
        self.hasher.update(message);
    }

    /// Append a field element (scalar) to the transcript.
    pub fn append_scalar(&mut self, label: &str, scalar: &FieldElement) {
        self.append_message(label, &scalar.to_bytes());
    }

    /// Append a curve point to the transcript.
    pub fn append_point(&mut self, label: &str, point: &CurvePoint) {
        self.append_message(label, &point.to_bytes());
    }

    /// Append a u64 value to the transcript.
    pub fn append_u64(&mut self, label: &str, value: u64) {
        self.append_message(label, &value.to_le_bytes());
    }

    /// Generate a challenge scalar from the current transcript state.
    ///
    /// This finalizes the current hash state to produce a challenge,
    /// then re-initializes with the hash output as seed for future challenges.
    /// This allows generating multiple sequential challenges from the same transcript.
    pub fn challenge_scalar(&mut self, label: &str) -> FieldElement {
        // Include the challenge label in the hash
        self.hasher.update(b"challenge:");
        self.hasher.update((label.len() as u32).to_le_bytes());
        self.hasher.update(label.as_bytes());

        // Finalize to get the challenge bytes
        let result = self.hasher.finalize_reset();

        // Re-initialize the hasher with the previous output as seed
        // This enables sequential challenge generation
        self.hasher.update(b"zkp-framework-transcript-chain:");
        self.hasher.update(&result);

        // Convert hash output to a field element (reduce mod p)
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result[..32]);
        let fr = ark_bn254::Fr::from_le_bytes_mod_order(&bytes);

        FieldElement::from(fr)
    }

    /// Get the protocol label.
    pub fn label(&self) -> &str {
        &self.label
    }
}

impl std::fmt::Debug for Transcript {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Transcript(\"{}\")", self.label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic() {
        let mut t1 = Transcript::new("test-protocol");
        t1.append_scalar("value", &FieldElement::from_u64(42));
        let c1 = t1.challenge_scalar("challenge");

        let mut t2 = Transcript::new("test-protocol");
        t2.append_scalar("value", &FieldElement::from_u64(42));
        let c2 = t2.challenge_scalar("challenge");

        assert_eq!(c1, c2);
    }

    #[test]
    fn test_different_messages_different_challenges() {
        let mut t1 = Transcript::new("test");
        t1.append_scalar("value", &FieldElement::from_u64(1));
        let c1 = t1.challenge_scalar("c");

        let mut t2 = Transcript::new("test");
        t2.append_scalar("value", &FieldElement::from_u64(2));
        let c2 = t2.challenge_scalar("c");

        assert_ne!(c1, c2);
    }

    #[test]
    fn test_domain_separation() {
        let mut t1 = Transcript::new("protocol-A");
        t1.append_scalar("value", &FieldElement::from_u64(42));
        let c1 = t1.challenge_scalar("c");

        let mut t2 = Transcript::new("protocol-B");
        t2.append_scalar("value", &FieldElement::from_u64(42));
        let c2 = t2.challenge_scalar("c");

        assert_ne!(c1, c2);
    }

    #[test]
    fn test_sequential_challenges() {
        let mut t = Transcript::new("multi-round");
        t.append_scalar("v1", &FieldElement::from_u64(10));
        let c1 = t.challenge_scalar("round1");

        t.append_scalar("v2", &FieldElement::from_u64(20));
        let c2 = t.challenge_scalar("round2");

        // Sequential challenges should be different
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_challenge_is_nonzero() {
        // Challenges should essentially never be zero (probability 1/p ≈ 0)
        let mut t = Transcript::new("nonzero-test");
        t.append_scalar("value", &FieldElement::from_u64(1));
        let c = t.challenge_scalar("c");
        assert!(!c.is_zero());
    }

    #[test]
    fn test_point_absorption() {
        let g = CurvePoint::generator();
        let mut t = Transcript::new("point-test");
        t.append_point("pk", &g);
        let c = t.challenge_scalar("c");

        // Should produce a valid field element
        assert!(!c.is_zero());
    }
}
