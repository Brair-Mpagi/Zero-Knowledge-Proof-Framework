//! # Sudoku Proof Example
//!
//! Demonstrates: "I know a valid solution to this Sudoku puzzle"
//! Uses the full R1CS pipeline: circuit → constraints → witness → prove → verify

use zkp_core::field::FieldElement;
use zkp_core::circuit::Witness;
use zkp_core::dsl::stdlib::{build_sudoku_4x4_circuit, compute_sudoku_4x4_internals};
use zkp_core::prover::Prover;
use zkp_core::verifier::Verifier;

fn main() {
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║     Zero-Knowledge Sudoku Proof Demo (4×4)          ║");
    println!("╚══════════════════════════════════════════════════════╝\n");

    // === The Puzzle ===
    // 0 = unknown cell
    let puzzle: [u64; 16] = [
        1, 0, 0, 4,
        0, 4, 0, 0,
        0, 0, 4, 0,
        4, 0, 0, 1,
    ];

    // === The Solution (SECRET!) ===
    let solution: [u64; 16] = [
        1, 2, 3, 4,
        3, 4, 1, 2,
        2, 1, 4, 3,
        4, 3, 2, 1,
    ];

    println!("=== Puzzle ===");
    print_grid(&puzzle);
    println!();

    println!("=== Solution (PRIVATE — only prover sees this) ===");
    print_grid(&solution);
    println!();

    // === Build Circuit ===
    println!("=== Building Circuit ===");
    let (builder, info) = build_sudoku_4x4_circuit();
    println!("{}", builder.stats());

    let r1cs = builder.build();
    println!("R1CS generated: {} constraints over {} variables",
        r1cs.num_constraints(), r1cs.num_variables());
    println!("{}", r1cs.sparsity_stats());

    // === Generate Witness ===
    println!("=== Generating Witness ===");
    let public: Vec<FieldElement> = puzzle.iter().map(|&v| FieldElement::from_u64(v)).collect();
    let private: Vec<FieldElement> = solution.iter().map(|&v| FieldElement::from_u64(v)).collect();
    let internals = compute_sudoku_4x4_internals(&puzzle, &solution);

    let witness = Witness::new(&public, &private, &internals);
    match witness.validate(&r1cs) {
        Ok(()) => println!("✓ Witness satisfies all R1CS constraints"),
        Err(e) => { println!("✗ Witness invalid: {}", e); return; }
    }
    println!();

    // === Generate Proof ===
    println!("=== Generating Zero-Knowledge Proof ===");
    let start = std::time::Instant::now();
    let proof = Prover::prove(&r1cs, &witness);
    let proving_time = start.elapsed();
    println!("✓ Proof generated in {:?}", proving_time);
    println!("  Constraints proven: {}", proof.metadata.num_constraints);
    println!("  Proof size: {} bytes", proof.metadata.proof_size_bytes.unwrap_or(0));
    println!();

    // === Verify Proof ===
    println!("=== Verifying Proof (without seeing the solution!) ===");
    let start = std::time::Instant::now();
    let result = Verifier::verify_detailed(&r1cs, &proof);
    let verify_time = start.elapsed();

    println!("Verification result: {} (took {:?})",
        if result.valid { "✓ VALID" } else { "✗ INVALID" },
        verify_time);
    println!();

    // === What the Verifier Sees ===
    println!("=== What the Verifier Sees ===");
    println!("The puzzle (public):");
    print_grid(&puzzle);
    println!("Solution: ████████████████ [HIDDEN]");
    println!("Proof status: VALID — the prover knows a solution!");
    println!();

    // === Negative Test ===
    println!("=== Negative Test: Tampered Proof ===");
    let mut bad_proof = proof.clone();
    bad_proof.public_inputs[0] = FieldElement::from_u64(99);
    let bad_result = Verifier::verify(&r1cs, &bad_proof);
    println!("Tampered proof: {} {}",
        if bad_result { "✓" } else { "✗" },
        if bad_result { "ACCEPTED (BUG!)" } else { "REJECTED (correct)" });
}

fn print_grid(grid: &[u64; 16]) {
    println!("┌───┬───┬───┬───┐");
    for row in 0..4 {
        print!("│");
        for col in 0..4 {
            let val = grid[row * 4 + col];
            if val == 0 {
                print!(" · │");
            } else {
                print!(" {} │", val);
            }
        }
        println!();
        if row < 3 {
            if row == 1 {
                println!("├───┼───┼───┼───┤");
            } else {
                println!("├───┼───┼───┼───┤");
            }
        }
    }
    println!("└───┴───┴───┴───┘");
}
