//! # Standard Library Gadgets
//!
//! Pre-built circuit components for common operations.
//! These are used by the DSL compiler and can be called directly.

use crate::field::FieldElement;
use crate::circuit::{CircuitBuilder, Variable, LinearCombination};

/// Build a 4×4 Sudoku verification circuit.
///
/// Public inputs: 16 grid values (0 = unknown, 1-4 = given clue)
/// Private inputs: 16 solution values
/// Internal variables: inverse witnesses for nonzero checks
///
/// Constraints:
/// 1. Given clues must match solution
/// 2. All solution values in {1, 2, 3, 4}
/// 3. Each row has all different values
/// 4. Each column has all different values
/// 5. Each 2×2 box has all different values
pub fn build_sudoku_4x4_circuit() -> (CircuitBuilder, SudokuCircuitInfo) {
    let mut builder = CircuitBuilder::new();

    // Allocate public inputs: the puzzle grid (0 = blank)
    let mut grid = Vec::new();
    for i in 0..16 {
        grid.push(builder.alloc_public_input_named(&format!("grid_{}", i)));
    }

    // Allocate private inputs: the solution
    let mut solution = Vec::new();
    for i in 0..16 {
        solution.push(builder.alloc_private_input_named(&format!("sol_{}", i)));
    }

    // Constraint 1: Given clues must match solution.
    // For each cell: if grid[i] != 0, then grid[i] == solution[i]
    // We encode this as: grid[i] * (grid[i] - solution[i]) = 0
    // If grid[i] = 0, constraint is trivially satisfied.
    // If grid[i] != 0, then grid[i] - solution[i] must be 0.
    for i in 0..16 {
        let diff = LinearCombination::from_variable(grid[i])
            - LinearCombination::from_variable(solution[i]);
        builder.add_constraint_labeled(
            LinearCombination::from_variable(grid[i]),
            diff,
            LinearCombination::zero(),
            &format!("clue_match_{}", i),
        );
    }

    // Constraint 2: All solution values in {1, 2, 3, 4}
    // (sol - 1)(sol - 2)(sol - 3)(sol - 4) = 0
    // We break this into intermediate multiplications:
    for i in 0..16 {
        // t1 = (sol - 1)
        let t1 = builder.alloc_internal_named(&format!("range_t1_{}", i));
        let sol_minus_1 = LinearCombination::from_variable(solution[i])
            - LinearCombination::from_constant(FieldElement::from_u64(1));
        builder.add_constraint(
            sol_minus_1,
            LinearCombination::from_variable(Variable::One),
            LinearCombination::from_variable(t1),
        );

        // t2 = (sol - 2)
        let t2 = builder.alloc_internal_named(&format!("range_t2_{}", i));
        let sol_minus_2 = LinearCombination::from_variable(solution[i])
            - LinearCombination::from_constant(FieldElement::from_u64(2));
        builder.add_constraint(
            sol_minus_2,
            LinearCombination::from_variable(Variable::One),
            LinearCombination::from_variable(t2),
        );

        // t3 = (sol - 3)
        let t3 = builder.alloc_internal_named(&format!("range_t3_{}", i));
        let sol_minus_3 = LinearCombination::from_variable(solution[i])
            - LinearCombination::from_constant(FieldElement::from_u64(3));
        builder.add_constraint(
            sol_minus_3,
            LinearCombination::from_variable(Variable::One),
            LinearCombination::from_variable(t3),
        );

        // t4 = (sol - 4)
        let t4 = builder.alloc_internal_named(&format!("range_t4_{}", i));
        let sol_minus_4 = LinearCombination::from_variable(solution[i])
            - LinearCombination::from_constant(FieldElement::from_u64(4));
        builder.add_constraint(
            sol_minus_4,
            LinearCombination::from_variable(Variable::One),
            LinearCombination::from_variable(t4),
        );

        // p1 = t1 * t2
        let p1 = builder.alloc_internal_named(&format!("range_p1_{}", i));
        builder.mul(t1, t2, p1);

        // p2 = t3 * t4
        let p2 = builder.alloc_internal_named(&format!("range_p2_{}", i));
        builder.mul(t3, t4, p2);

        // p1 * p2 = 0
        builder.add_constraint_labeled(
            LinearCombination::from_variable(p1),
            LinearCombination::from_variable(p2),
            LinearCombination::zero(),
            &format!("range_check_{}", i),
        );
    }

    // Constraint 3: Row uniqueness
    // Rows: [0..3], [4..7], [8..11], [12..15]
    let rows = vec![
        vec![0, 1, 2, 3],
        vec![4, 5, 6, 7],
        vec![8, 9, 10, 11],
        vec![12, 13, 14, 15],
    ];

    for (row_idx, row) in rows.iter().enumerate() {
        for j in 0..row.len() {
            for k in (j + 1)..row.len() {
                builder.assert_different(solution[row[j]], solution[row[k]]);
            }
        }
    }

    // Constraint 4: Column uniqueness
    let cols = vec![
        vec![0, 4, 8, 12],
        vec![1, 5, 9, 13],
        vec![2, 6, 10, 14],
        vec![3, 7, 11, 15],
    ];

    for (col_idx, col) in cols.iter().enumerate() {
        for j in 0..col.len() {
            for k in (j + 1)..col.len() {
                builder.assert_different(solution[col[j]], solution[col[k]]);
            }
        }
    }

    // Constraint 5: Box uniqueness (2×2 boxes)
    let boxes = vec![
        vec![0, 1, 4, 5],
        vec![2, 3, 6, 7],
        vec![8, 9, 12, 13],
        vec![10, 11, 14, 15],
    ];

    for (box_idx, bx) in boxes.iter().enumerate() {
        for j in 0..bx.len() {
            for k in (j + 1)..bx.len() {
                builder.assert_different(solution[bx[j]], solution[bx[k]]);
            }
        }
    }

    let info = SudokuCircuitInfo {
        grid_vars: grid,
        solution_vars: solution,
        stats: builder.stats(),
    };

    (builder, info)
}

/// Information about the Sudoku circuit for the visualizer.
#[derive(Clone, Debug)]
pub struct SudokuCircuitInfo {
    pub grid_vars: Vec<Variable>,
    pub solution_vars: Vec<Variable>,
    pub stats: crate::circuit::CircuitStats,
}

/// Compute witness internal values for a 4×4 Sudoku circuit.
pub fn compute_sudoku_4x4_internals(
    grid: &[u64; 16],
    solution: &[u64; 16],
) -> Vec<FieldElement> {
    let mut internals = Vec::new();

    // Range check internals: for each cell, t1..t4, p1, p2
    for i in 0..16 {
        let s = solution[i] as i64;
        let t1 = s - 1;
        let t2 = s - 2;
        let t3 = s - 3;
        let t4 = s - 4;
        let p1 = t1 * t2;
        let p2 = t3 * t4;

        internals.push(FieldElement::from(t1));
        internals.push(FieldElement::from(t2));
        internals.push(FieldElement::from(t3));
        internals.push(FieldElement::from(t4));
        internals.push(FieldElement::from(p1));
        internals.push(FieldElement::from(p2));
    }

    // Uniqueness inverse witnesses
    let groups = vec![
        // Rows
        vec![0, 1, 2, 3], vec![4, 5, 6, 7],
        vec![8, 9, 10, 11], vec![12, 13, 14, 15],
        // Columns
        vec![0, 4, 8, 12], vec![1, 5, 9, 13],
        vec![2, 6, 10, 14], vec![3, 7, 11, 15],
        // Boxes
        vec![0, 1, 4, 5], vec![2, 3, 6, 7],
        vec![8, 9, 12, 13], vec![10, 11, 14, 15],
    ];

    for group in &groups {
        for j in 0..group.len() {
            for k in (j + 1)..group.len() {
                let diff = solution[group[j]] as i64 - solution[group[k]] as i64;
                let diff_fe = FieldElement::from(diff);
                let inv = diff_fe.inverse()
                    .expect("Solution values in same group must be different");
                internals.push(inv);
            }
        }
    }

    internals
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::Witness;

    #[test]
    fn test_sudoku_circuit_builds() {
        let (builder, info) = build_sudoku_4x4_circuit();
        let stats = builder.stats();
        assert!(stats.num_constraints > 0);
        assert_eq!(stats.num_public_inputs, 16);
        assert_eq!(stats.num_private_inputs, 16);
        println!("Sudoku 4x4 circuit: {}", stats);
    }

    #[test]
    fn test_sudoku_valid_solution() {
        let (builder, _) = build_sudoku_4x4_circuit();
        let r1cs = builder.build();

        // Valid 4×4 Sudoku:
        // 1 2 | 3 4
        // 3 4 | 1 2
        // ----+----
        // 2 1 | 4 3
        // 4 3 | 2 1
        let grid = [1, 2, 3, 4, 3, 4, 1, 2, 2, 1, 4, 3, 4, 3, 2, 1u64];
        let solution = grid;

        let public: Vec<FieldElement> = grid.iter().map(|&v| FieldElement::from_u64(v)).collect();
        let private: Vec<FieldElement> = solution.iter().map(|&v| FieldElement::from_u64(v)).collect();
        let internals = compute_sudoku_4x4_internals(&grid, &solution);

        let witness = Witness::new(&public, &private, &internals);
        assert!(witness.validate(&r1cs).is_ok(), "Valid Sudoku should satisfy R1CS");
    }

    #[test]
    fn test_sudoku_with_blanks() {
        let (builder, _) = build_sudoku_4x4_circuit();
        let r1cs = builder.build();

        // Puzzle with blanks (0)
        let grid = [1, 0, 0, 4, 0, 4, 0, 0, 0, 0, 4, 0, 4, 0, 0, 1u64];
        let solution = [1, 2, 3, 4, 3, 4, 1, 2, 2, 1, 4, 3, 4, 3, 2, 1u64];

        let public: Vec<FieldElement> = grid.iter().map(|&v| FieldElement::from_u64(v)).collect();
        let private: Vec<FieldElement> = solution.iter().map(|&v| FieldElement::from_u64(v)).collect();
        let internals = compute_sudoku_4x4_internals(&grid, &solution);

        let witness = Witness::new(&public, &private, &internals);
        assert!(witness.validate(&r1cs).is_ok(), "Sudoku with blanks should satisfy");
    }
}
