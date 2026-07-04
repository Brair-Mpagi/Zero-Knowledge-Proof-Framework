//! # ZKP Core Library
//!
//! A from-first-principles implementation of a zero-knowledge proof framework.
//!
//! ## Architecture
//!
//! ```text
//! Statement (e.g. "I know Sudoku solution")
//!           │
//!           ▼
//!    ┌────────────────┐
//!    │ Circuit Builder │  developer/DSL defines variables + gates
//!    └───────┬────────┘
//!            ▼
//!    ┌────────────────────┐
//!    │ Constraint Generator│  emits R1CS matrices (A, B, C)
//!    └───────┬────────────┘
//!            ▼
//!    ┌────────────────────┐        private inputs
//!    │  Witness Generator  │◄───────────────────
//!    └───────┬────────────┘
//!            ▼
//!    ┌────────────────┐   commitments,     ┌─────────────────┐
//!    │     Prover      │──challenges────►  │     Verifier      │
//!    │ (Fiat-Shamir    │◄──responses─────  │ (checks           │
//!    │  non-interactive)│                  │  Fiat-Shamir hash)│
//!    └────────────────┘                    └─────────────────┘
//!            │
//!            ▼
//!      Proof object (serialized: commitments + responses)
//! ```
//!
//! ## Modules
//!
//! - [`field`] — Finite field arithmetic over BN254's scalar field
//! - [`curve`] — Elliptic curve group operations on BN254's G1
//! - [`commitment`] — Pedersen commitment scheme
//! - [`transcript`] — Fiat-Shamir transcript for non-interactive proofs
//! - [`sigma`] — Sigma protocols (Schnorr, Pedersen opening, DLEQ)
//! - [`circuit`] — Circuit builder, R1CS generator, witness computation
//! - [`prover`] — R1CS satisfaction proof generation
//! - [`verifier`] — R1CS satisfaction proof verification
//! - [`dsl`] — Simple declarative circuit description language

pub mod field;
pub mod curve;
pub mod commitment;
pub mod transcript;
pub mod sigma;
pub mod circuit;
pub mod prover;
pub mod verifier;
pub mod dsl;

/// Re-export commonly used types for convenience.
pub mod prelude {
    pub use crate::field::FieldElement;
    pub use crate::curve::CurvePoint;
    pub use crate::commitment::{PedersenParams, PedersenCommitment};
    pub use crate::transcript::Transcript;
    pub use crate::sigma::{SchnorrProof, PedersenOpeningProof};
    pub use crate::circuit::{CircuitBuilder, Variable, LinearCombination, R1CS, Witness};
    pub use crate::prover::{Prover, Proof};
    pub use crate::verifier::Verifier;
}
