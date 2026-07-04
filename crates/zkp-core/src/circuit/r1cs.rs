//! # Rank-1 Constraint System (R1CS)
//!
//! Converts a circuit into the standard R1CS form: A·z ∘ B·z = C·z
//!
//! ## R1CS Representation
//!
//! Given a circuit with `m` constraints and `n` variables, R1CS consists of:
//! - Three matrices A, B, C ∈ F^{m×n}
//! - A witness vector z ∈ F^n where z = (1, public_inputs..., private_inputs..., internals...)
//!
//! For each constraint i: (A_i · z) × (B_i · z) = (C_i · z)
//!
//! The matrices are sparse — each row has only a few nonzero entries
//! (corresponding to the variables in that constraint's linear combinations).

use crate::field::FieldElement;
use crate::circuit::{CircuitBuilder, Variable, LinearCombination, Constraint};
use serde::{Serialize, Deserialize};

/// A sparse matrix row: list of (column_index, value) pairs.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SparseRow {
    pub entries: Vec<(usize, FieldElement)>,
}

impl SparseRow {
    /// Evaluate the dot product of this row with a vector.
    pub fn dot(&self, z: &[FieldElement]) -> FieldElement {
        let mut sum = FieldElement::zero();
        for &(col, ref val) in &self.entries {
            if col < z.len() {
                sum = sum + *val * z[col];
            }
        }
        sum
    }
}

/// Rank-1 Constraint System.
///
/// Represents a system of constraints of the form:
/// For each i: (A_i · z) × (B_i · z) = (C_i · z)
///
/// Where z is the full variable assignment vector.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct R1CS {
    /// Number of public input variables
    pub num_public: usize,
    /// Number of private input variables  
    pub num_private: usize,
    /// Number of internal (intermediate) variables
    pub num_internal: usize,
    /// Matrix A (one sparse row per constraint)
    pub a_matrix: Vec<SparseRow>,
    /// Matrix B (one sparse row per constraint)
    pub b_matrix: Vec<SparseRow>,
    /// Matrix C (one sparse row per constraint)
    pub c_matrix: Vec<SparseRow>,
    /// Constraint labels (for debugging/visualization)
    pub labels: Vec<Option<String>>,
    /// Variable labels (for debugging/visualization)
    pub var_labels: Vec<(Variable, String)>,
}

impl R1CS {
    /// Build an R1CS from a CircuitBuilder.
    pub fn from_builder(builder: CircuitBuilder) -> Self {
        let (num_public, num_private, num_internal, constraints, var_labels) =
            builder.into_parts();

        let mut a_matrix = Vec::with_capacity(constraints.len());
        let mut b_matrix = Vec::with_capacity(constraints.len());
        let mut c_matrix = Vec::with_capacity(constraints.len());
        let mut labels = Vec::with_capacity(constraints.len());

        for constraint in &constraints {
            a_matrix.push(Self::lc_to_sparse_row(
                &constraint.a, num_public, num_private,
            ));
            b_matrix.push(Self::lc_to_sparse_row(
                &constraint.b, num_public, num_private,
            ));
            c_matrix.push(Self::lc_to_sparse_row(
                &constraint.c, num_public, num_private,
            ));
            labels.push(constraint.label.clone());
        }

        R1CS {
            num_public,
            num_private,
            num_internal,
            a_matrix,
            b_matrix,
            c_matrix,
            labels,
            var_labels,
        }
    }

    /// Convert a linear combination to a sparse row.
    fn lc_to_sparse_row(
        lc: &LinearCombination,
        num_public: usize,
        num_private: usize,
    ) -> SparseRow {
        let mut entries: Vec<(usize, FieldElement)> = lc
            .terms
            .iter()
            .map(|(coeff, var)| (var.index(num_public, num_private), *coeff))
            .collect();

        // Merge duplicate column indices
        entries.sort_by_key(|(col, _)| *col);
        let mut merged = Vec::new();
        for (col, val) in entries {
            if let Some(last) = merged.last_mut() {
                let (last_col, last_val): &mut (usize, FieldElement) = last;
                if *last_col == col {
                    *last_val = *last_val + val;
                    continue;
                }
            }
            merged.push((col, val));
        }

        // Remove zero entries
        merged.retain(|(_, val)| !val.is_zero());

        SparseRow { entries: merged }
    }

    /// Total number of variables in the system (including the constant wire).
    pub fn num_variables(&self) -> usize {
        1 + self.num_public + self.num_private + self.num_internal
    }

    /// Number of constraints.
    pub fn num_constraints(&self) -> usize {
        self.a_matrix.len()
    }

    /// Check if a witness vector satisfies all constraints.
    ///
    /// For each constraint i, checks: (A_i · z) × (B_i · z) = (C_i · z)
    pub fn is_satisfied(&self, z: &[FieldElement]) -> bool {
        if z.len() != self.num_variables() {
            return false;
        }

        // z[0] must be 1 (the constant wire)
        if !z[0].is_one() {
            return false;
        }

        for i in 0..self.num_constraints() {
            let a_val = self.a_matrix[i].dot(z);
            let b_val = self.b_matrix[i].dot(z);
            let c_val = self.c_matrix[i].dot(z);

            if a_val * b_val != c_val {
                return false;
            }
        }

        true
    }

    /// Check satisfaction and return the first failing constraint (for debugging).
    pub fn check_satisfaction(&self, z: &[FieldElement]) -> Result<(), String> {
        if z.len() != self.num_variables() {
            return Err(format!(
                "witness length {} != expected {}",
                z.len(),
                self.num_variables()
            ));
        }

        if !z[0].is_one() {
            return Err("z[0] must be 1 (constant wire)".to_string());
        }

        for i in 0..self.num_constraints() {
            let a_val = self.a_matrix[i].dot(z);
            let b_val = self.b_matrix[i].dot(z);
            let c_val = self.c_matrix[i].dot(z);

            if a_val * b_val != c_val {
                let label = self.labels[i]
                    .as_deref()
                    .unwrap_or("unlabeled");
                return Err(format!(
                    "Constraint {} ({}) failed: ({}) * ({}) ≠ ({})",
                    i,
                    label,
                    a_val,
                    b_val,
                    c_val,
                ));
            }
        }

        Ok(())
    }

    /// Get the public inputs from a witness vector.
    pub fn public_inputs(&self, z: &[FieldElement]) -> Vec<FieldElement> {
        z[1..1 + self.num_public].to_vec()
    }

    /// Get the private inputs from a witness vector.
    pub fn private_inputs(&self, z: &[FieldElement]) -> Vec<FieldElement> {
        let start = 1 + self.num_public;
        z[start..start + self.num_private].to_vec()
    }

    /// Sparsity statistics (for benchmarking / display).
    pub fn sparsity_stats(&self) -> SparsityStats {
        let total_entries: usize = self.a_matrix.iter().map(|r| r.entries.len()).sum::<usize>()
            + self.b_matrix.iter().map(|r| r.entries.len()).sum::<usize>()
            + self.c_matrix.iter().map(|r| r.entries.len()).sum::<usize>();

        let total_possible = 3 * self.num_constraints() * self.num_variables();
        let density = if total_possible > 0 {
            total_entries as f64 / total_possible as f64
        } else {
            0.0
        };

        SparsityStats {
            num_constraints: self.num_constraints(),
            num_variables: self.num_variables(),
            total_nonzero_entries: total_entries,
            density,
        }
    }

    /// Export the R1CS to a JSON representation (for the web visualizer).
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    /// Get variable label by variable.
    pub fn get_var_label(&self, var: &Variable) -> Option<&str> {
        self.var_labels
            .iter()
            .find(|(v, _)| v == var)
            .map(|(_, label)| label.as_str())
    }
}

/// Statistics about the R1CS matrix sparsity.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SparsityStats {
    pub num_constraints: usize,
    pub num_variables: usize,
    pub total_nonzero_entries: usize,
    pub density: f64,
}

impl std::fmt::Display for SparsityStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "R1CS Sparsity:")?;
        writeln!(f, "  Constraints:    {}", self.num_constraints)?;
        writeln!(f, "  Variables:      {}", self.num_variables)?;
        writeln!(f, "  Nonzero entries: {}", self.total_nonzero_entries)?;
        writeln!(f, "  Density:        {:.4}%", self.density * 100.0)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::CircuitBuilder;

    #[test]
    fn test_simple_mul_r1cs() {
        // Circuit: x * x = y (prove knowledge of square root)
        let mut builder = CircuitBuilder::new();
        let x = builder.alloc_private_input();
        let y = builder.alloc_public_input();
        builder.mul(x, x, y);

        let r1cs = builder.build();
        assert_eq!(r1cs.num_constraints(), 1);
        assert_eq!(r1cs.num_variables(), 3); // 1 + 1 pub + 1 prv

        // Valid witness: x=3, y=9  → z = [1, 9, 3]
        let z = vec![
            FieldElement::one(),      // constant wire
            FieldElement::from_u64(9), // y (public)
            FieldElement::from_u64(3), // x (private)
        ];
        assert!(r1cs.is_satisfied(&z));

        // Invalid witness: x=3, y=10
        let z_bad = vec![
            FieldElement::one(),
            FieldElement::from_u64(10),
            FieldElement::from_u64(3),
        ];
        assert!(!r1cs.is_satisfied(&z_bad));
    }

    #[test]
    fn test_addition_constraint() {
        // Circuit: a + b = c
        let mut builder = CircuitBuilder::new();
        let a = builder.alloc_private_input();
        let b = builder.alloc_private_input();
        let c = builder.alloc_public_input();
        builder.add(a, b, c);

        let r1cs = builder.build();

        // Valid: a=3, b=5, c=8
        let z = vec![
            FieldElement::one(),
            FieldElement::from_u64(8), // c (public)
            FieldElement::from_u64(3), // a (private)
            FieldElement::from_u64(5), // b (private)
        ];
        assert!(r1cs.is_satisfied(&z));
    }

    #[test]
    fn test_assert_bool() {
        let mut builder = CircuitBuilder::new();
        let x = builder.alloc_private_input();
        builder.assert_bool(x);

        let r1cs = builder.build();

        // x = 0 should satisfy
        let z0 = vec![FieldElement::one(), FieldElement::zero()];
        assert!(r1cs.is_satisfied(&z0));

        // x = 1 should satisfy
        let z1 = vec![FieldElement::one(), FieldElement::one()];
        assert!(r1cs.is_satisfied(&z1));

        // x = 2 should NOT satisfy
        let z2 = vec![FieldElement::one(), FieldElement::from_u64(2)];
        assert!(!r1cs.is_satisfied(&z2));
    }

    #[test]
    fn test_assert_nonzero() {
        let mut builder = CircuitBuilder::new();
        let x = builder.alloc_private_input();
        let _inv = builder.assert_nonzero(x);

        let r1cs = builder.build();

        // x = 5, inv = 1/5
        let five = FieldElement::from_u64(5);
        let inv_five = five.inverse().unwrap();
        let z = vec![FieldElement::one(), five, inv_five];
        assert!(r1cs.is_satisfied(&z));
    }

    #[test]
    fn test_sparsity_stats() {
        let mut builder = CircuitBuilder::new();
        let x = builder.alloc_private_input();
        let y = builder.alloc_public_input();
        builder.mul(x, x, y);

        let r1cs = builder.build();
        let stats = r1cs.sparsity_stats();
        assert_eq!(stats.num_constraints, 1);
        assert!(stats.density < 1.0);
    }
}
