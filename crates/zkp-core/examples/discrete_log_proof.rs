//! # Discrete Log Proof Example
//!
//! Demonstrates: "I know x such that g^x = Y"
//! This is the canonical Schnorr/Sigma protocol example.

use zkp_core::field::FieldElement;
use zkp_core::curve::CurvePoint;
use zkp_core::sigma::{SchnorrProof, schnorr_proof_transcript};

fn main() {
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║     Zero-Knowledge Discrete Log Proof Demo          ║");
    println!("╚══════════════════════════════════════════════════════╝\n");

    // === Setup ===
    let g = CurvePoint::generator();
    let secret = FieldElement::from_u64(42);
    let public_key = g.scalar_mul(&secret);

    println!("=== Setup ===");
    println!("Generator (g):     {:?}", g);
    println!("Secret (x):        {} [PRIVATE]", secret);
    println!("Public key (Y=g^x): {:?}", public_key);
    println!();

    // === Proof Generation ===
    println!("=== Generating Proof ===");
    println!("Statement: \"I know x such that g^x = Y\"");
    println!();

    let proof = SchnorrProof::prove(&g, &public_key, &secret);

    let transcript = schnorr_proof_transcript(&g, &public_key, &proof);
    for step in &transcript {
        println!("Step {}: {} — {}", step.step_number, step.phase, step.description);
        for (name, value) in &step.values {
            println!("  {} = {}", name, value);
        }
        println!();
    }

    // === Verification ===
    println!("=== Verification ===");
    let valid = proof.verify(&g, &public_key);
    println!("Proof valid: {} {}", if valid { "✓" } else { "✗" }, if valid { "ACCEPTED" } else { "REJECTED" });
    println!();

    // === Negative Test: Tampered Proof ===
    println!("=== Negative Test: Tampered Proof ===");
    let mut tampered = proof.clone();
    tampered.response = tampered.response + FieldElement::one();
    let tampered_valid = tampered.verify(&g, &public_key);
    println!("Tampered proof valid: {} {}", 
        if tampered_valid { "✓" } else { "✗" },
        if tampered_valid { "ACCEPTED (BUG!)" } else { "REJECTED (correct)" });
    println!();

    // === Negative Test: Wrong Public Key ===
    println!("=== Negative Test: Wrong Public Key ===");
    let wrong_pk = g.scalar_mul(&FieldElement::from_u64(99));
    let wrong_pk_valid = proof.verify(&g, &wrong_pk);
    println!("Wrong PK valid: {} {}",
        if wrong_pk_valid { "✓" } else { "✗" },
        if wrong_pk_valid { "ACCEPTED (BUG!)" } else { "REJECTED (correct)" });
    println!();

    // === JSON Export ===
    println!("=== Proof JSON ===");
    println!("{}", proof.to_json());
}
