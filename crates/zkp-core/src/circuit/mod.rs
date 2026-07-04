//! # Circuit System
//!
//! Arithmetic circuit builder, R1CS constraint generator, and witness computation.
//!
//! ## Architecture
//!
//! 1. **CircuitBuilder** — API for defining variables and adding constraints
//! 2. **R1CS** — Rank-1 Constraint System: sparse matrices (A, B, C) where A·z ∘ B·z = C·z
//! 3. **Witness** — Full variable assignment that satisfies the constraints

pub mod r1cs;
pub mod witness;

use crate::field::FieldElement;
use serde::{Serialize, Deserialize};
use std::fmt;

/// Index into the variable vector z = (1, public_inputs..., private_inputs..., internal...)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Variable {
    /// The constant wire (always 1)
    One,
    /// A public input variable
    Public(usize),
    /// A private input (witness) variable
    Private(usize),
    /// An internal (intermediate) variable
    Internal(usize),
}

impl Variable {
    /// Convert to an index in the flattened variable vector z.
    ///
    /// Layout: z = [1, public_0, public_1, ..., private_0, ..., internal_0, ...]
    pub fn index(&self, num_public: usize, num_private: usize) -> usize {
        match self {
            Variable::One => 0,
            Variable::Public(i) => 1 + i,
            Variable::Private(i) => 1 + num_public + i,
            Variable::Internal(i) => 1 + num_public + num_private + i,
        }
    }
}

impl fmt::Display for Variable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Variable::One => write!(f, "1"),
            Variable::Public(i) => write!(f, "pub_{}", i),
            Variable::Private(i) => write!(f, "prv_{}", i),
            Variable::Internal(i) => write!(f, "int_{}", i),
        }
    }
}

/// A linear combination of variables: Σ cᵢ·xᵢ
///
/// Represents an expression like `3·x₁ + 5·x₂ - 2·x₃`.
/// R1CS constraints are of the form `A·z ∘ B·z = C·z`
/// where A, B, C are each a vector of linear combinations.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LinearCombination {
    /// Terms: (coefficient, variable) pairs
    pub terms: Vec<(FieldElement, Variable)>,
}

impl LinearCombination {
    /// Create an empty linear combination (zero).
    pub fn zero() -> Self {
        LinearCombination { terms: Vec::new() }
    }

    /// Create a linear combination from a single variable with coefficient 1.
    pub fn from_variable(var: Variable) -> Self {
        LinearCombination {
            terms: vec![(FieldElement::one(), var)],
        }
    }

    /// Create a linear combination representing a constant value.
    pub fn from_constant(value: FieldElement) -> Self {
        if value.is_zero() {
            Self::zero()
        } else {
            LinearCombination {
                terms: vec![(value, Variable::One)],
            }
        }
    }

    /// Add a term: `coeff · var`
    pub fn add_term(&mut self, coeff: FieldElement, var: Variable) {
        self.terms.push((coeff, var));
    }

    /// Evaluate the linear combination given a variable assignment.
    pub fn evaluate(&self, assignment: &[FieldElement]) -> FieldElement {
        let mut result = FieldElement::zero();
        for (coeff, var) in &self.terms {
            let var_idx = match var {
                Variable::One => 0,
                Variable::Public(i) => 1 + i,
                Variable::Private(i) => {
                    // We need context to know num_public, so we use a flat index
                    // This is handled by the R1CS evaluator
                    panic!("Use R1CS::evaluate for full evaluation with proper indexing");
                }
                Variable::Internal(i) => {
                    panic!("Use R1CS::evaluate for full evaluation with proper indexing");
                }
            };
            result = result + *coeff * assignment[var_idx];
        }
        result
    }

    /// Evaluate given the full variable vector and dimension info.
    pub fn evaluate_with_dims(
        &self,
        z: &[FieldElement],
        num_public: usize,
        num_private: usize,
    ) -> FieldElement {
        let mut result = FieldElement::zero();
        for (coeff, var) in &self.terms {
            let idx = var.index(num_public, num_private);
            if idx < z.len() {
                result = result + *coeff * z[idx];
            }
        }
        result
    }
}

// Operator overloading for building linear combinations ergonomically

impl std::ops::Add for LinearCombination {
    type Output = Self;
    fn add(mut self, rhs: Self) -> Self {
        self.terms.extend(rhs.terms);
        self
    }
}

impl std::ops::Sub for LinearCombination {
    type Output = Self;
    fn sub(mut self, rhs: Self) -> Self {
        for (coeff, var) in rhs.terms {
            self.terms.push((coeff.negate(), var));
        }
        self
    }
}

impl std::ops::Mul<FieldElement> for LinearCombination {
    type Output = Self;
    fn mul(mut self, scalar: FieldElement) -> Self {
        for (coeff, _) in &mut self.terms {
            *coeff = *coeff * scalar;
        }
        self
    }
}

/// An R1CS constraint: `a · b = c` (where a, b, c are linear combinations).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Constraint {
    pub a: LinearCombination,
    pub b: LinearCombination,
    pub c: LinearCombination,
    /// Optional human-readable label for debugging
    pub label: Option<String>,
}

/// Builder for constructing arithmetic circuits.
///
/// Provides a high-level API for defining variables, adding constraints,
/// and building circuits that compile down to R1CS.
///
/// # Example
/// ```
/// use zkp_core::circuit::{CircuitBuilder, Variable};
/// use zkp_core::field::FieldElement;
///
/// let mut builder = CircuitBuilder::new();
/// let x = builder.alloc_private_input(); // Secret input
/// let y = builder.alloc_public_input();   // Public output
/// // Constraint: x * x = y  (prove knowledge of square root)
/// builder.mul(x, x, y);
/// let r1cs = builder.build();
/// ```
pub struct CircuitBuilder {
    /// Number of public input variables
    num_public: usize,
    /// Number of private input variables
    num_private: usize,
    /// Number of internal (intermediate) variables
    num_internal: usize,
    /// Accumulated constraints
    constraints: Vec<Constraint>,
    /// Variable labels for debugging
    var_labels: Vec<(Variable, String)>,
}

impl CircuitBuilder {
    /// Create a new empty circuit builder.
    pub fn new() -> Self {
        CircuitBuilder {
            num_public: 0,
            num_private: 0,
            num_internal: 0,
            constraints: Vec::new(),
            var_labels: Vec::new(),
        }
    }

    /// Allocate a new public input variable.
    pub fn alloc_public_input(&mut self) -> Variable {
        let var = Variable::Public(self.num_public);
        self.num_public += 1;
        var
    }

    /// Allocate a new public input variable with a label.
    pub fn alloc_public_input_named(&mut self, name: &str) -> Variable {
        let var = self.alloc_public_input();
        self.var_labels.push((var, name.to_string()));
        var
    }

    /// Allocate a new private input (witness) variable.
    pub fn alloc_private_input(&mut self) -> Variable {
        let var = Variable::Private(self.num_private);
        self.num_private += 1;
        var
    }

    /// Allocate a new private input variable with a label.
    pub fn alloc_private_input_named(&mut self, name: &str) -> Variable {
        let var = self.alloc_private_input();
        self.var_labels.push((var, name.to_string()));
        var
    }

    /// Allocate a new internal (intermediate) variable.
    pub fn alloc_internal(&mut self) -> Variable {
        let var = Variable::Internal(self.num_internal);
        self.num_internal += 1;
        var
    }

    /// Allocate a new internal variable with a label.
    pub fn alloc_internal_named(&mut self, name: &str) -> Variable {
        let var = self.alloc_internal();
        self.var_labels.push((var, name.to_string()));
        var
    }

    /// Add a raw R1CS constraint: `a · b = c`
    pub fn add_constraint(
        &mut self,
        a: LinearCombination,
        b: LinearCombination,
        c: LinearCombination,
    ) {
        self.constraints.push(Constraint {
            a,
            b,
            c,
            label: None,
        });
    }

    /// Add a labeled R1CS constraint: `a · b = c`
    pub fn add_constraint_labeled(
        &mut self,
        a: LinearCombination,
        b: LinearCombination,
        c: LinearCombination,
        label: &str,
    ) {
        self.constraints.push(Constraint {
            a,
            b,
            c,
            label: Some(label.to_string()),
        });
    }

    /// Multiplication gate: allocates output and constrains `a * b = out`.
    ///
    /// Returns the output variable.
    pub fn mul(&mut self, a: Variable, b: Variable, out: Variable) {
        self.add_constraint(
            LinearCombination::from_variable(a),
            LinearCombination::from_variable(b),
            LinearCombination::from_variable(out),
        );
    }

    /// Addition: constrains `a + b = out`.
    /// Encoded as: `(a + b) * 1 = out`
    pub fn add(&mut self, a: Variable, b: Variable, out: Variable) {
        let lc_a = LinearCombination::from_variable(a)
            + LinearCombination::from_variable(b);

        self.add_constraint(
            lc_a,
            LinearCombination::from_variable(Variable::One),
            LinearCombination::from_variable(out),
        );
    }

    /// Assert two variables are equal: `a = b`.
    /// Encoded as: `(a - b) * 1 = 0`
    pub fn assert_equal(&mut self, a: Variable, b: Variable) {
        let a_minus_b = LinearCombination::from_variable(a)
            - LinearCombination::from_variable(b);

        self.add_constraint_labeled(
            a_minus_b,
            LinearCombination::from_variable(Variable::One),
            LinearCombination::zero(),
            &format!("{} == {}", a, b),
        );
    }

    /// Assert a variable equals a constant value.
    /// Encoded as: `(a - constant) * 1 = 0`
    pub fn assert_constant(&mut self, a: Variable, value: FieldElement) {
        let lc = LinearCombination::from_variable(a)
            - LinearCombination::from_constant(value);

        self.add_constraint_labeled(
            lc,
            LinearCombination::from_variable(Variable::One),
            LinearCombination::zero(),
            &format!("{} == {}", a, value),
        );
    }

    /// Assert a variable is boolean (0 or 1).
    /// Encoded as: `a * (1 - a) = 0`
    pub fn assert_bool(&mut self, a: Variable) {
        let one_minus_a = LinearCombination::from_variable(Variable::One)
            - LinearCombination::from_variable(a);

        self.add_constraint_labeled(
            LinearCombination::from_variable(a),
            one_minus_a,
            LinearCombination::zero(),
            &format!("{} ∈ {{0, 1}}", a),
        );
    }

    /// Assert a variable is nonzero (by requiring an inverse exists).
    /// Allocates an internal variable `inv` and constrains `a * inv = 1`.
    ///
    /// Returns the inverse variable.
    pub fn assert_nonzero(&mut self, a: Variable) -> Variable {
        let inv = self.alloc_internal_named(&format!("inv({})", a));
        self.add_constraint_labeled(
            LinearCombination::from_variable(a),
            LinearCombination::from_variable(inv),
            LinearCombination::from_constant(FieldElement::one()),
            &format!("{} ≠ 0", a),
        );
        inv
    }

    /// Conditional selection: `out = cond ? a : b`
    /// Encoded as: `cond * (a - b) = out - b`
    ///
    /// Requires `cond` to be boolean (call `assert_bool` first).
    pub fn select(
        &mut self,
        cond: Variable,
        a: Variable,
        b: Variable,
        out: Variable,
    ) {
        let a_minus_b = LinearCombination::from_variable(a)
            - LinearCombination::from_variable(b);
        let out_minus_b = LinearCombination::from_variable(out)
            - LinearCombination::from_variable(b);

        self.add_constraint_labeled(
            LinearCombination::from_variable(cond),
            a_minus_b,
            out_minus_b,
            &format!("{} = {} ? {} : {}", out, cond, a, b),
        );
    }

    /// Assert two variables are different (a ≠ b).
    /// Allocates an inverse variable and constrains `(a - b) * inv = 1`.
    ///
    /// Returns the inverse variable.
    pub fn assert_different(&mut self, a: Variable, b: Variable) -> Variable {
        let inv = self.alloc_internal_named(&format!("inv({}-{})", a, b));
        let a_minus_b = LinearCombination::from_variable(a)
            - LinearCombination::from_variable(b);

        self.add_constraint_labeled(
            a_minus_b,
            LinearCombination::from_variable(inv),
            LinearCombination::from_constant(FieldElement::one()),
            &format!("{} ≠ {}", a, b),
        );
        inv
    }

    /// Build the circuit into an R1CS constraint system.
    pub fn build(self) -> r1cs::R1CS {
        r1cs::R1CS::from_builder(self)
    }

    /// Get the number of constraints.
    pub fn num_constraints(&self) -> usize {
        self.constraints.len()
    }

    /// Get the total number of variables (including the constant wire).
    pub fn num_variables(&self) -> usize {
        1 + self.num_public + self.num_private + self.num_internal
    }

    /// Get variable counts.
    pub fn variable_counts(&self) -> (usize, usize, usize) {
        (self.num_public, self.num_private, self.num_internal)
    }

    /// Get the constraints (for R1CS conversion).
    pub(crate) fn into_parts(self) -> (usize, usize, usize, Vec<Constraint>, Vec<(Variable, String)>) {
        (
            self.num_public,
            self.num_private,
            self.num_internal,
            self.constraints,
            self.var_labels,
        )
    }

    /// Circuit statistics for display.
    pub fn stats(&self) -> CircuitStats {
        CircuitStats {
            num_public_inputs: self.num_public,
            num_private_inputs: self.num_private,
            num_internal_variables: self.num_internal,
            num_constraints: self.constraints.len(),
            total_variables: self.num_variables(),
        }
    }
}

impl Default for CircuitBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Circuit statistics for display and benchmarking.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitStats {
    pub num_public_inputs: usize,
    pub num_private_inputs: usize,
    pub num_internal_variables: usize,
    pub num_constraints: usize,
    pub total_variables: usize,
}

impl fmt::Display for CircuitStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Circuit Statistics:")?;
        writeln!(f, "  Public inputs:     {}", self.num_public_inputs)?;
        writeln!(f, "  Private inputs:    {}", self.num_private_inputs)?;
        writeln!(f, "  Internal vars:     {}", self.num_internal_variables)?;
        writeln!(f, "  Total variables:   {}", self.total_variables)?;
        writeln!(f, "  Constraints:       {}", self.num_constraints)?;
        Ok(())
    }
}

// Re-export key types from submodules
pub use r1cs::R1CS;
pub use witness::Witness;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_variable_indexing() {
        let num_public = 2;
        let num_private = 3;

        assert_eq!(Variable::One.index(num_public, num_private), 0);
        assert_eq!(Variable::Public(0).index(num_public, num_private), 1);
        assert_eq!(Variable::Public(1).index(num_public, num_private), 2);
        assert_eq!(Variable::Private(0).index(num_public, num_private), 3);
        assert_eq!(Variable::Private(2).index(num_public, num_private), 5);
        assert_eq!(Variable::Internal(0).index(num_public, num_private), 6);
    }

    #[test]
    fn test_linear_combination_ops() {
        let lc1 = LinearCombination::from_variable(Variable::Public(0));
        let lc2 = LinearCombination::from_variable(Variable::Public(1));
        let sum = lc1 + lc2;
        assert_eq!(sum.terms.len(), 2);
    }

    #[test]
    fn test_circuit_builder_allocation() {
        let mut builder = CircuitBuilder::new();
        let x = builder.alloc_public_input();
        let y = builder.alloc_private_input();
        let z = builder.alloc_internal();

        assert_eq!(x, Variable::Public(0));
        assert_eq!(y, Variable::Private(0));
        assert_eq!(z, Variable::Internal(0));
        assert_eq!(builder.num_variables(), 4); // 1 + pub + prv + int
    }

    #[test]
    fn test_circuit_builder_simple_mul() {
        let mut builder = CircuitBuilder::new();
        let x = builder.alloc_private_input();
        let y = builder.alloc_public_input();
        builder.mul(x, x, y); // x * x = y

        assert_eq!(builder.num_constraints(), 1);
        let stats = builder.stats();
        assert_eq!(stats.num_public_inputs, 1);
        assert_eq!(stats.num_private_inputs, 1);
    }
}
