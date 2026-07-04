//! # Wallet Ownership Proof Example
//!
//! Demonstrates: "I own the private key for this public key"
//! Uses Schnorr-signature-style proof with domain separation for wallet identity.

use zkp_core::field::FieldElement;
use zkp_core::curve::CurvePoint;
use zkp_core::sigma::SchnorrProof;
use zkp_core::transcript::Transcript;

fn main() {
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║     Zero-Knowledge Wallet Ownership Proof           ║");
    println!("╚══════════════════════════════════════════════════════╝\n");

    // === Wallet Setup ===
    let mut rng = rand::thread_rng();
    let private_key = FieldElement::random(&mut rng);
    let g = CurvePoint::generator();
    let public_key = g.scalar_mul(&private_key);

    println!("=== Wallet ===");
    println!("Public Key:  {:?}", public_key);
    println!("Private Key: ████████████████ [SECRET]");
    println!();

    // === Domain-separated wallet identity ===
    let wallet_address = {
        let mut t = Transcript::new("wallet-address-v1");
        t.append_point("public_key", &public_key);
        let addr_scalar = t.challenge_scalar("address");
        format!("0xZK{}", &addr_scalar.to_decimal()[..16])
    };
    println!("Wallet Address: {}", wallet_address);
    println!();

    // === Generate Proof ===
    println!("=== Generating Wallet Ownership Proof ===");
    println!("Statement: \"I own the private key for wallet {}\"", wallet_address);
    println!();

    let proof = SchnorrProof::prove(&g, &public_key, &private_key);
    println!("✓ Proof generated");
    println!("  Commitment: {:?}", proof.commitment);
    println!("  Challenge:  {:?}", proof.challenge);
    println!("  Response:   {:?}", proof.response);
    println!();

    // === Verification ===
    println!("=== Verification ===");
    let valid = proof.verify(&g, &public_key);
    println!("Ownership proof: {} {}",
        if valid { "✓" } else { "✗" },
        if valid { "VERIFIED — This entity controls the wallet" } else { "FAILED" });
    println!();

    // === Impersonation Attempt ===
    println!("=== Attack: Impersonation Attempt ===");
    let attacker_key = FieldElement::from_u64(999);
    let fake_proof = SchnorrProof::prove(&g, &public_key, &attacker_key);
    let fake_valid = fake_proof.verify(&g, &public_key);
    println!("Fake proof: {} {}",
        if fake_valid { "✓" } else { "✗" },
        if fake_valid { "ACCEPTED (SECURITY BUG!)" } else { "REJECTED — Impersonation blocked" });
    println!();

    // === JSON Export ===
    println!("=== Proof JSON ===");
    println!("{}", proof.to_json());
}
