//! Benchmarks for the ZKP framework.

use criterion::{criterion_group, criterion_main, Criterion};
use zkp_core::field::FieldElement;
use zkp_core::curve::CurvePoint;
use zkp_core::commitment::PedersenParams;
use zkp_core::sigma::SchnorrProof;
use zkp_core::circuit::{CircuitBuilder, Witness};
use zkp_core::dsl::stdlib::{build_sudoku_4x4_circuit, compute_sudoku_4x4_internals};
use zkp_core::prover::Prover;
use zkp_core::verifier::Verifier;

fn bench_field_arithmetic(c: &mut Criterion) {
    let a = FieldElement::from_u64(123456789);
    let b = FieldElement::from_u64(987654321);

    c.bench_function("field_mul", |bench| {
        bench.iter(|| a * b);
    });

    c.bench_function("field_inverse", |bench| {
        bench.iter(|| a.inverse());
    });
}

fn bench_pedersen_commit(c: &mut Criterion) {
    let params = PedersenParams::new();
    let msg = FieldElement::from_u64(42);
    let r = FieldElement::from_u64(12345);

    c.bench_function("pedersen_commit", |bench| {
        bench.iter(|| params.commit(&msg, &r));
    });
}

fn bench_schnorr(c: &mut Criterion) {
    let g = CurvePoint::generator();
    let secret = FieldElement::from_u64(42);
    let pk = g.scalar_mul(&secret);

    c.bench_function("schnorr_prove", |bench| {
        bench.iter(|| SchnorrProof::prove(&g, &pk, &secret));
    });

    let proof = SchnorrProof::prove(&g, &pk, &secret);
    c.bench_function("schnorr_verify", |bench| {
        bench.iter(|| proof.verify(&g, &pk));
    });
}

fn bench_sudoku(c: &mut Criterion) {
    let puzzle: [u64; 16] = [1,0,0,4, 0,4,0,0, 0,0,4,0, 4,0,0,1];
    let solution: [u64; 16] = [1,2,3,4, 3,4,1,2, 2,1,4,3, 4,3,2,1];

    let (builder, _) = build_sudoku_4x4_circuit();
    let r1cs = builder.build();

    let public: Vec<FieldElement> = puzzle.iter().map(|&v| FieldElement::from_u64(v)).collect();
    let private: Vec<FieldElement> = solution.iter().map(|&v| FieldElement::from_u64(v)).collect();
    let internals = compute_sudoku_4x4_internals(&puzzle, &solution);
    let witness = Witness::new(&public, &private, &internals);

    c.bench_function("sudoku_prove", |bench| {
        bench.iter(|| Prover::prove(&r1cs, &witness));
    });

    let proof = Prover::prove(&r1cs, &witness);
    c.bench_function("sudoku_verify", |bench| {
        bench.iter(|| Verifier::verify(&r1cs, &proof));
    });
}

criterion_group!(benches, bench_field_arithmetic, bench_pedersen_commit, bench_schnorr, bench_sudoku);
criterion_main!(benches);
