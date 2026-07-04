//! # WASM Bindings for the ZKP Framework
//!
//! Provides JavaScript-callable functions for all proof operations.
//! Compiled with `wasm-pack build --target web`.

use wasm_bindgen::prelude::*;
use zkp_core::field::FieldElement;
use zkp_core::curve::CurvePoint;
use zkp_core::sigma::{SchnorrProof, schnorr_proof_transcript};
use zkp_core::circuit::Witness;
use zkp_core::dsl::stdlib::{build_sudoku_4x4_circuit, compute_sudoku_4x4_internals};
use zkp_core::prover::Prover;
use zkp_core::verifier::Verifier;

/// Generate a Schnorr discrete-log proof.
/// Returns JSON: { proof, public_key, generator, valid }
#[wasm_bindgen]
pub fn prove_discrete_log(secret: u64) -> String {
    let g = CurvePoint::generator();
    let secret_fe = FieldElement::from_u64(secret);
    let pk = g.scalar_mul(&secret_fe);

    let proof = SchnorrProof::prove(&g, &pk, &secret_fe);
    let valid = proof.verify(&g, &pk);

    let transcript = schnorr_proof_transcript(&g, &pk, &proof);

    serde_json::json!({
        "proof": serde_json::to_value(&proof).unwrap_or_default(),
        "public_key": format!("{:?}", pk),
        "valid": valid,
        "transcript": transcript.iter().map(|s| {
            serde_json::json!({
                "step": s.step_number,
                "phase": s.phase,
                "description": s.description,
                "values": s.values,
            })
        }).collect::<Vec<_>>(),
    }).to_string()
}

/// Verify a Schnorr proof from JSON.
#[wasm_bindgen]
pub fn verify_discrete_log(proof_json: &str, secret: u64) -> bool {
    let g = CurvePoint::generator();
    let secret_fe = FieldElement::from_u64(secret);
    let pk = g.scalar_mul(&secret_fe);

    if let Ok(proof) = serde_json::from_str::<SchnorrProof>(proof_json) {
        proof.verify(&g, &pk)
    } else {
        false
    }
}

/// Generate a 4×4 Sudoku ZK proof.
/// Input: puzzle and solution as comma-separated strings of 16 numbers each.
/// Returns JSON with proof details.
#[wasm_bindgen]
pub fn prove_sudoku(puzzle_str: &str, solution_str: &str) -> String {
    let puzzle: Vec<u64> = puzzle_str.split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    let solution: Vec<u64> = solution_str.split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    if puzzle.len() != 16 || solution.len() != 16 {
        return serde_json::json!({ "error": "Need exactly 16 values each" }).to_string();
    }

    let mut puzzle_arr = [0u64; 16];
    let mut solution_arr = [0u64; 16];
    puzzle_arr.copy_from_slice(&puzzle);
    solution_arr.copy_from_slice(&solution);

    let (builder, _) = build_sudoku_4x4_circuit();
    let stats = builder.stats();
    let r1cs = builder.build();

    let public: Vec<FieldElement> = puzzle.iter().map(|&v| FieldElement::from_u64(v)).collect();
    let private: Vec<FieldElement> = solution.iter().map(|&v| FieldElement::from_u64(v)).collect();
    let internals = compute_sudoku_4x4_internals(&puzzle_arr, &solution_arr);
    let witness = Witness::new(&public, &private, &internals);

    match witness.validate(&r1cs) {
        Ok(()) => {},
        Err(e) => return serde_json::json!({ "error": e }).to_string(),
    }

    let proof = Prover::prove(&r1cs, &witness);
    let valid = Verifier::verify(&r1cs, &proof);

    serde_json::json!({
        "valid": valid,
        "num_constraints": stats.num_constraints,
        "num_variables": stats.total_variables,
        "proving_time_ms": proof.metadata.proving_time_ms,
        "proof_size_bytes": proof.metadata.proof_size_bytes,
        "puzzle": puzzle,
        "solution_hidden": true,
    }).to_string()
}

/// Get circuit information for a given circuit type.
#[wasm_bindgen]
pub fn get_circuit_info(circuit_type: &str) -> String {
    match circuit_type {
        "sudoku" => {
            let (builder, _) = build_sudoku_4x4_circuit();
            let stats = builder.stats();
            let r1cs = builder.build();
            let sparsity = r1cs.sparsity_stats();

            serde_json::json!({
                "name": "4×4 Sudoku",
                "public_inputs": stats.num_public_inputs,
                "private_inputs": stats.num_private_inputs,
                "internal_variables": stats.num_internal_variables,
                "total_variables": stats.total_variables,
                "constraints": stats.num_constraints,
                "density": sparsity.density,
                "nonzero_entries": sparsity.total_nonzero_entries,
            }).to_string()
        }
        _ => serde_json::json!({ "error": "Unknown circuit type" }).to_string(),
    }
}

/// Compile DSL source and return circuit info.
#[wasm_bindgen]
pub fn compile_dsl(source: &str) -> String {
    match zkp_core::dsl::parse(source) {
        Ok(program) => {
            match zkp_core::dsl::compile(&program) {
                Ok(builder) => {
                    let stats = builder.stats();
                    serde_json::json!({
                        "name": program.name,
                        "public_inputs": stats.num_public_inputs,
                        "private_inputs": stats.num_private_inputs,
                        "internal_variables": stats.num_internal_variables,
                        "constraints": stats.num_constraints,
                        "total_variables": stats.total_variables,
                    }).to_string()
                }
                Err(e) => serde_json::json!({ "error": e }).to_string(),
            }
        }
        Err(e) => serde_json::json!({ "error": e }).to_string(),
    }
}

/// Generate a wallet ownership proof.
#[wasm_bindgen]
pub fn prove_wallet_ownership() -> String {
    let mut rng = rand::thread_rng();
    let private_key = FieldElement::random(&mut rng);
    let g = CurvePoint::generator();
    let pk = g.scalar_mul(&private_key);

    let proof = SchnorrProof::prove(&g, &pk, &private_key);
    let valid = proof.verify(&g, &pk);

    serde_json::json!({
        "public_key": format!("{:?}", pk),
        "proof": serde_json::to_value(&proof).unwrap_or_default(),
        "valid": valid,
    }).to_string()
}
