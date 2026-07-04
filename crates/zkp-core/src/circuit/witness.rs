//! # Witness Generator
//!
//! Computes the full variable assignment (witness) for a circuit given inputs.
//!
//! The witness vector z = (1, public_inputs..., private_inputs..., internals...)
//! must satisfy all R1CS constraints: A·z ∘ B·z = C·z.

use crate::field::FieldElement;
use crate::circuit::r1cs::R1CS;
use serde::{Serialize, Deserialize};

/// A witness (full variable assignment) for an R1CS circuit.
///
/// Contains the complete vector z that satisfies all constraints.
/// The witness is divided into:
/// - z[0] = 1 (constant wire)
/// - z[1..1+num_public] = public inputs
/// - z[1+num_public..1+num_public+num_private] = private inputs (secret)
/// - z[1+num_public+num_private..] = internal/intermediate variables
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Witness {
    /// The full variable assignment vector
    pub values: Vec<FieldElement>,
    /// Number of public inputs
    pub num_public: usize,
    /// Number of private inputs
    pub num_private: usize,
}

impl Witness {
    /// Create a witness from public and private inputs, computing internal variables.
    ///
    /// The `compute_internals` callback is responsible for filling in the
    /// internal variable values given the public and private inputs.
    pub fn new(
        public_inputs: &[FieldElement],
        private_inputs: &[FieldElement],
        internal_values: &[FieldElement],
    ) -> Self {
        let mut values = Vec::with_capacity(1 + public_inputs.len() + private_inputs.len() + internal_values.len());
        values.push(FieldElement::one()); // Constant wire
        values.extend_from_slice(public_inputs);
        values.extend_from_slice(private_inputs);
        values.extend_from_slice(internal_values);

        Witness {
            values,
            num_public: public_inputs.len(),
            num_private: private_inputs.len(),
        }
    }

    /// Create a witness by providing all values directly.
    pub fn from_values(values: Vec<FieldElement>, num_public: usize, num_private: usize) -> Self {
        assert!(values[0].is_one(), "z[0] must be 1");
        Witness {
            values,
            num_public,
            num_private,
        }
    }

    /// Get the full witness vector z.
    pub fn as_slice(&self) -> &[FieldElement] {
        &self.values
    }

    /// Get public inputs only.
    pub fn public_inputs(&self) -> &[FieldElement] {
        &self.values[1..1 + self.num_public]
    }

    /// Get private inputs only.
    pub fn private_inputs(&self) -> &[FieldElement] {
        let start = 1 + self.num_public;
        &self.values[start..start + self.num_private]
    }

    /// Get internal variable values.
    pub fn internal_values(&self) -> &[FieldElement] {
        let start = 1 + self.num_public + self.num_private;
        &self.values[start..]
    }

    /// Validate the witness against an R1CS system.
    pub fn validate(&self, r1cs: &R1CS) -> Result<(), String> {
        r1cs.check_satisfaction(&self.values)
    }

    /// Create a redacted version for display (hides private inputs).
    pub fn redacted_display(&self) -> Vec<(String, String)> {
        let mut display = Vec::new();
        display.push(("z[0] (constant)".to_string(), "1".to_string()));

        for i in 0..self.num_public {
            display.push((
                format!("z[{}] (public_{})", 1 + i, i),
                self.values[1 + i].to_decimal(),
            ));
        }

        for i in 0..self.num_private {
            display.push((
                format!("z[{}] (private_{})", 1 + self.num_public + i, i),
                "████████ [REDACTED]".to_string(),
            ));
        }

        let internal_start = 1 + self.num_public + self.num_private;
        for i in internal_start..self.values.len() {
            display.push((
                format!("z[{}] (internal_{})", i, i - internal_start),
                "████████ [REDACTED]".to_string(),
            ));
        }

        display
    }
}

/// Builder for computing internal variable values given a circuit.
///
/// For circuits where internal variables can be computed from inputs
/// (e.g., inverses for assert_nonzero), this helper automates that computation.
pub struct WitnessBuilder {
    values: Vec<FieldElement>,
    num_public: usize,
    num_private: usize,
    num_internal: usize,
}

impl WitnessBuilder {
    /// Create a new witness builder.
    pub fn new(num_public: usize, num_private: usize, num_internal: usize) -> Self {
        let total = 1 + num_public + num_private + num_internal;
        let mut values = vec![FieldElement::zero(); total];
        values[0] = FieldElement::one(); // Constant wire

        WitnessBuilder {
            values,
            num_public,
            num_private,
            num_internal,
        }
    }

    /// Set a public input value.
    pub fn set_public(&mut self, index: usize, value: FieldElement) {
        assert!(index < self.num_public, "public index out of range");
        self.values[1 + index] = value;
    }

    /// Set a private input value.
    pub fn set_private(&mut self, index: usize, value: FieldElement) {
        assert!(index < self.num_private, "private index out of range");
        self.values[1 + self.num_public + index] = value;
    }

    /// Set an internal variable value.
    pub fn set_internal(&mut self, index: usize, value: FieldElement) {
        assert!(index < self.num_internal, "internal index out of range");
        self.values[1 + self.num_public + self.num_private + index] = value;
    }

    /// Get a value by its variable index in the z vector.
    pub fn get(&self, z_index: usize) -> FieldElement {
        self.values[z_index]
    }

    /// Build the witness.
    pub fn build(self) -> Witness {
        Witness {
            values: self.values,
            num_public: self.num_public,
            num_private: self.num_private,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::CircuitBuilder;

    #[test]
    fn test_witness_creation() {
        let public = vec![FieldElement::from_u64(9)];
        let private = vec![FieldElement::from_u64(3)];
        let internal = vec![];

        let witness = Witness::new(&public, &private, &internal);
        assert_eq!(witness.public_inputs(), &public);
        assert_eq!(witness.private_inputs(), &private);
        assert!(witness.values[0].is_one());
    }

    #[test]
    fn test_witness_validation() {
        // x * x = y
        let mut builder = CircuitBuilder::new();
        let x = builder.alloc_private_input();
        let y = builder.alloc_public_input();
        builder.mul(x, x, y);
        let r1cs = builder.build();

        // Valid witness
        let witness = Witness::new(
            &[FieldElement::from_u64(25)],  // y = 25
            &[FieldElement::from_u64(5)],   // x = 5
            &[],
        );
        assert!(witness.validate(&r1cs).is_ok());

        // Invalid witness
        let bad_witness = Witness::new(
            &[FieldElement::from_u64(26)],  // y = 26 (wrong!)
            &[FieldElement::from_u64(5)],   // x = 5
            &[],
        );
        assert!(bad_witness.validate(&r1cs).is_err());
    }

    #[test]
    fn test_witness_builder() {
        let mut wb = WitnessBuilder::new(1, 1, 0);
        wb.set_public(0, FieldElement::from_u64(25));
        wb.set_private(0, FieldElement::from_u64(5));

        let witness = wb.build();
        assert_eq!(witness.public_inputs()[0], FieldElement::from_u64(25));
        assert_eq!(witness.private_inputs()[0], FieldElement::from_u64(5));
    }

    #[test]
    fn test_redacted_display() {
        let witness = Witness::new(
            &[FieldElement::from_u64(42)],
            &[FieldElement::from_u64(7)],
            &[],
        );
        let display = witness.redacted_display();

        // Public should be visible
        assert!(display[1].1.contains("42"));
        // Private should be redacted
        assert!(display[2].1.contains("REDACTED"));
    }
}
