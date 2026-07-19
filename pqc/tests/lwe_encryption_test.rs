use pqc::lwe_encryption::{
    chi, encode_error_sample, reduce_mod, LweParameters, ModMatrix, ModVector, N, Q,
    SAMPLE_COUNT, SIGMA,
};

#[test]
fn demo_parameters_match_the_specification() {
    let parameters = LweParameters::default();

    assert_eq!(parameters.dimension, N);
    assert_eq!(parameters.modulus, Q);
    assert_eq!(parameters.sample_count, SAMPLE_COUNT);
    assert_eq!(parameters.sigma, SIGMA);
    assert!(parameters.is_valid());
}

#[test]
fn modular_reduction_handles_negative_values() {
    assert_eq!(reduce_mod(-1, Q), 126);
    assert_eq!(reduce_mod(127, Q), 0);
    assert_eq!(reduce_mod(128, Q), 1);
}

#[test]
fn dot_product_is_computed_modulo_q() {
    let left = ModVector::new(vec![126, 2], Q);
    let right = ModVector::new(vec![2, 64], Q);

    assert_eq!(left.dot(&right), 126);
}

#[test]
fn chi_returns_value_in_range() {
    let result = chi(2.0, 1000);
    assert!(
        (-10..10).contains(&result),
        "chi value {} out of range",
        result
    );
}

#[test]
fn chi_produces_different_values() {
    let values: Vec<i64> = (0..20).map(|_| chi(2.0, 1000)).collect();
    let all_same = values.windows(2).all(|w| w[0] == w[1]);
    assert!(!all_same, "chi should not produce identical values repeatedly");
}

#[test]
fn encode_error_sample_rounds_properly() {
    assert_eq!(encode_error_sample(3.7), 4);
    assert_eq!(encode_error_sample(-1.3), -1);
}

#[test]
fn mod_matrix_creation_and_access() {
    let m = ModMatrix::new(2, 3, vec![1, 2, 3, 4, 5, 6], Q);
    assert_eq!(m.dimensions(), (2, 3));
    assert_eq!(m.get(0, 0), 1);
    assert_eq!(m.get(0, 2), 3);
    assert_eq!(m.get(1, 1), 5);
}

#[test]
fn mod_matrix_reduces_values_on_creation() {
    let m = ModMatrix::new(1, 2, vec![127, -1], Q);
    assert_eq!(m.get(0, 0), 0);
    assert_eq!(m.get(0, 1), 126);
}

