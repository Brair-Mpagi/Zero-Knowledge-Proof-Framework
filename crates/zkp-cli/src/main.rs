//! # ZKP Framework CLI
//!
//! Command-line interface for generating and verifying zero-knowledge proofs.

use clap::{Parser, Subcommand};
use colored::Colorize;
use zkp_core::field::FieldElement;
use zkp_core::curve::CurvePoint;
use zkp_core::sigma::SchnorrProof;
use zkp_core::circuit::Witness;
use zkp_core::dsl::stdlib::{build_sudoku_4x4_circuit, compute_sudoku_4x4_internals};
use zkp_core::prover::Prover;
use zkp_core::verifier::Verifier;

#[derive(Parser)]
#[command(name = "zkp")]
#[command(about = "Zero-Knowledge Proof Framework CLI", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate and verify a discrete-log proof
    DiscreteLog {
        /// The secret value (witness)
        #[arg(short, long, default_value = "42")]
        secret: u64,
    },
    /// Generate and verify a Sudoku proof
    Sudoku,
    /// Generate and verify a wallet ownership proof
    Wallet,
    /// Show circuit information
    CircuitInfo {
        /// Circuit type: sudoku
        #[arg(short, long, default_value = "sudoku")]
        circuit: String,
    },
    /// Compile a DSL file to a circuit
    Compile {
        /// Path to DSL source file
        #[arg(short, long)]
        file: String,
    },
    /// Run benchmarks
    Bench,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::DiscreteLog { secret } => cmd_discrete_log(secret),
        Commands::Sudoku => cmd_sudoku(),
        Commands::Wallet => cmd_wallet(),
        Commands::CircuitInfo { circuit } => cmd_circuit_info(&circuit),
        Commands::Compile { file } => cmd_compile(&file),
        Commands::Bench => cmd_bench(),
    }
}

fn cmd_discrete_log(secret_val: u64) {
    println!("{}", "═══ Discrete Log Proof ═══".cyan().bold());
    println!();

    let g = CurvePoint::generator();
    let secret = FieldElement::from_u64(secret_val);
    let pk = g.scalar_mul(&secret);

    println!("{} g^{} = {:?}", "Statement:".yellow(), secret_val, pk);
    println!();

    let start = std::time::Instant::now();
    let proof = SchnorrProof::prove(&g, &pk, &secret);
    let prove_time = start.elapsed();

    println!("{} Generated in {:?}", "Proof:".green(), prove_time);
    println!("  Commitment: {:?}", proof.commitment);
    println!("  Challenge:  {:?}", proof.challenge);
    println!("  Response:   {:?}", proof.response);
    println!();

    let start = std::time::Instant::now();
    let valid = proof.verify(&g, &pk);
    let verify_time = start.elapsed();

    if valid {
        println!("{} Verified in {:?}", "✓ VALID".green().bold(), verify_time);
    } else {
        println!("{} (took {:?})", "✗ INVALID".red().bold(), verify_time);
    }
    println!();

    // Negative test
    let mut tampered = proof.clone();
    tampered.response = tampered.response + FieldElement::one();
    let tampered_valid = tampered.verify(&g, &pk);
    println!("{} Tampered proof: {}",
        "Soundness:".yellow(),
        if tampered_valid { "ACCEPTED (BUG!)".red().to_string() } else { "REJECTED ✓".green().to_string() });
}

fn cmd_sudoku() {
    println!("{}", "═══ 4×4 Sudoku Proof ═══".cyan().bold());
    println!();

    let puzzle: [u64; 16] = [1,0,0,4, 0,4,0,0, 0,0,4,0, 4,0,0,1];
    let solution: [u64; 16] = [1,2,3,4, 3,4,1,2, 2,1,4,3, 4,3,2,1];

    println!("{}", "Puzzle:".yellow());
    for r in 0..4 {
        for c in 0..4 {
            let v = puzzle[r*4+c];
            if v == 0 { print!(" ."); } else { print!(" {}", v); }
        }
        println!();
    }
    println!();

    let (builder, _) = build_sudoku_4x4_circuit();
    let stats = builder.stats();
    println!("{} {} constraints, {} variables",
        "Circuit:".yellow(), stats.num_constraints, stats.total_variables);

    let r1cs = builder.build();

    let public: Vec<FieldElement> = puzzle.iter().map(|&v| FieldElement::from_u64(v)).collect();
    let private: Vec<FieldElement> = solution.iter().map(|&v| FieldElement::from_u64(v)).collect();
    let internals = compute_sudoku_4x4_internals(&puzzle, &solution);
    let witness = Witness::new(&public, &private, &internals);

    match witness.validate(&r1cs) {
        Ok(()) => println!("{}", "✓ Witness valid".green()),
        Err(e) => { println!("{} {}", "✗ Witness invalid:".red(), e); return; }
    }

    let start = std::time::Instant::now();
    let proof = Prover::prove(&r1cs, &witness);
    let prove_time = start.elapsed();
    println!("{} Generated in {:?} ({} bytes)",
        "Proof:".green(), prove_time, proof.metadata.proof_size_bytes.unwrap_or(0));

    let start = std::time::Instant::now();
    let valid = Verifier::verify(&r1cs, &proof);
    let verify_time = start.elapsed();

    if valid {
        println!("{} Verified in {:?}", "✓ VALID".green().bold(), verify_time);
    } else {
        println!("{} (took {:?})", "✗ INVALID".red().bold(), verify_time);
    }
}

fn cmd_wallet() {
    println!("{}", "═══ Wallet Ownership Proof ═══".cyan().bold());
    println!();

    let mut rng = rand::thread_rng();
    let private_key = FieldElement::random(&mut rng);
    let g = CurvePoint::generator();
    let pk = g.scalar_mul(&private_key);

    println!("{} {:?}", "Public Key:".yellow(), pk);

    let proof = SchnorrProof::prove(&g, &pk, &private_key);
    let valid = proof.verify(&g, &pk);

    if valid {
        println!("{}", "✓ Wallet ownership verified".green().bold());
    } else {
        println!("{}", "✗ Verification failed".red().bold());
    }

    // Attack test
    let fake_key = FieldElement::from_u64(999);
    let fake_proof = SchnorrProof::prove(&g, &pk, &fake_key);
    let fake_valid = fake_proof.verify(&g, &pk);
    println!("{} {}",
        "Impersonation:".yellow(),
        if fake_valid { "ACCEPTED (BUG!)".red().to_string() } else { "BLOCKED ✓".green().to_string() });
}

fn cmd_circuit_info(circuit: &str) {
    println!("{}", "═══ Circuit Information ═══".cyan().bold());
    match circuit {
        "sudoku" => {
            let (builder, _) = build_sudoku_4x4_circuit();
            println!("{}", builder.stats());
            let r1cs = builder.build();
            println!("{}", r1cs.sparsity_stats());
        }
        _ => println!("Unknown circuit: {}", circuit),
    }
}

fn cmd_compile(file: &str) {
    println!("{}", "═══ DSL Compiler ═══".cyan().bold());
    match std::fs::read_to_string(file) {
        Ok(source) => {
            match zkp_core::dsl::parse(&source) {
                Ok(program) => {
                    println!("{} Parsed circuit '{}'", "✓".green(), program.name);
                    match zkp_core::dsl::compile(&program) {
                        Ok(builder) => {
                            println!("{}", builder.stats());
                        }
                        Err(e) => println!("{} {}", "Compile error:".red(), e),
                    }
                }
                Err(e) => println!("{} {}", "Parse error:".red(), e),
            }
        }
        Err(e) => println!("{} {}", "File error:".red(), e),
    }
}

fn cmd_bench() {
    println!("{}", "═══ Benchmarks ═══".cyan().bold());
    println!();

    // Schnorr proof benchmark
    let g = CurvePoint::generator();
    let secret = FieldElement::from_u64(42);
    let pk = g.scalar_mul(&secret);

    let start = std::time::Instant::now();
    for _ in 0..100 {
        let _ = SchnorrProof::prove(&g, &pk, &secret);
    }
    let schnorr_time = start.elapsed() / 100;
    println!("Schnorr prove (avg):  {:?}", schnorr_time);

    let proof = SchnorrProof::prove(&g, &pk, &secret);
    let start = std::time::Instant::now();
    for _ in 0..100 {
        let _ = proof.verify(&g, &pk);
    }
    let schnorr_verify = start.elapsed() / 100;
    println!("Schnorr verify (avg): {:?}", schnorr_verify);
    println!();

    // Sudoku proof benchmark
    let puzzle: [u64; 16] = [1,0,0,4, 0,4,0,0, 0,0,4,0, 4,0,0,1];
    let solution: [u64; 16] = [1,2,3,4, 3,4,1,2, 2,1,4,3, 4,3,2,1];

    let (builder, _) = build_sudoku_4x4_circuit();
    let r1cs = builder.build();
    let public: Vec<FieldElement> = puzzle.iter().map(|&v| FieldElement::from_u64(v)).collect();
    let private: Vec<FieldElement> = solution.iter().map(|&v| FieldElement::from_u64(v)).collect();
    let internals = compute_sudoku_4x4_internals(&puzzle, &solution);
    let witness = Witness::new(&public, &private, &internals);

    let start = std::time::Instant::now();
    let proof = Prover::prove(&r1cs, &witness);
    let sudoku_prove = start.elapsed();
    println!("Sudoku prove:  {:?} ({} constraints)", sudoku_prove, r1cs.num_constraints());

    let start = std::time::Instant::now();
    let _ = Verifier::verify(&r1cs, &proof);
    let sudoku_verify = start.elapsed();
    println!("Sudoku verify: {:?}", sudoku_verify);
    println!("Proof size:    {} bytes", proof.metadata.proof_size_bytes.unwrap_or(0));
}
