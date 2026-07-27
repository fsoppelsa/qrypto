//! Educational building blocks of Learning With Errors (LWE).

use rand::Rng;
use rand_distr::Normal;

pub const N: usize = 8; // Dimension of the LWE secret and public vectors.
pub const Q: i64 = 127; // Prime modulus for arithmetic in Z_q.
pub const SIGMA: f64 = 1.0; // Standard deviation of the discrete error distribution.
pub const SAMPLE_COUNT: usize = 42; // Number of LWE samples: floor(1.1 * N * ln(Q)).

/// Parameters for the educational LWE instance.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LweParameters {
    pub dimension: usize,
    pub modulus: i64,
    pub sample_count: usize,
    pub sigma: f64,
}

impl Default for LweParameters {
    fn default() -> Self {
        Self {
            dimension: N,
            modulus: Q,
            sample_count: SAMPLE_COUNT,
            sigma: SIGMA,
        }
    }
}

impl LweParameters {
    /// Returns whether these parameters describe a usable modular ring.
    pub fn is_valid(self) -> bool {
        self.dimension > 0 && self.modulus > 1 && self.sample_count > 0 && self.sigma > 0.0
    }
}

/// Reduces `value` to its canonical representative in the range 0..modulus.
pub fn reduce_mod(value: i64, modulus: i64) -> i64 {
    assert!(modulus > 1, "the modulus must be greater than one");
    value.rem_euclid(modulus)
}

/// Rounds a real-valued error sample to an integer for use in Z_q.
pub fn encode_error_sample(sample: f64) -> i64 {
    sample.round() as i64
}

/// Draws a signed noise value from a discrete Gaussian centred at zero.
///
/// Samples from the standard normal N(0, 1), scales by `stdev`,
/// and rounds to the nearest integer.  The result is **not** reduced
/// modulo `modulus` so that the noise remains a small signed value.
pub fn chi(stdev: f64, _modulus: i64) -> i64 {
    let normal = Normal::new(0.0, 1.0).expect("invalid normal distribution parameters");
    let sample: f64 = rand::thread_rng().sample(normal);
    (sample * stdev).round() as i64
}

/// A vector whose entries are represented canonically in Z_q.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModVector {
    values: Vec<i64>,
    modulus: i64,
}

impl ModVector {
    /// Creates a vector and reduces every supplied value modulo `modulus`.
    pub fn new(values: Vec<i64>, modulus: i64) -> Self {
        assert!(modulus > 1, "the modulus must be greater than one");

        Self {
            values: values
                .into_iter()
                .map(|value| reduce_mod(value, modulus))
                .collect(),
            modulus,
        }
    }

    /// Returns the number of entries in this vector.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns true when the vector has no entries.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Returns the canonical modular value at `index`.
    pub fn get(&self, index: usize) -> i64 {
        self.values[index]
    }

    /// Computes an inner product in Z_q.
    pub fn dot(&self, other: &Self) -> i64 {
        assert_eq!(self.modulus, other.modulus, "moduli must match");
        assert_eq!(self.len(), other.len(), "vector dimensions must match");

        self.values
            .iter()
            .zip(&other.values)
            .fold(0, |sum, (&left, &right)| {
                reduce_mod(sum + left * right, self.modulus)
            })
    }
}

// ---------------------------------------------------------------------------

/// A row-major matrix over Z_q, suitable for holding public LWE samples.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModMatrix {
    rows: usize,
    columns: usize,
    values: Vec<i64>,
    modulus: i64,
}

impl ModMatrix {
    /// Creates a matrix from row-major values, reducing each value modulo `modulus`.
    pub fn new(rows: usize, columns: usize, values: Vec<i64>, modulus: i64) -> Self {
        assert!(modulus > 1, "the modulus must be greater than one");
        assert_eq!(
            values.len(),
            rows * columns,
            "matrix dimensions must match values"
        );

        Self {
            rows,
            columns,
            values: values
                .into_iter()
                .map(|value| reduce_mod(value, modulus))
                .collect(),
            modulus,
        }
    }

    /// Returns the matrix dimensions as `(rows, columns)`.
    pub fn dimensions(&self) -> (usize, usize) {
        (self.rows, self.columns)
    }

    /// Returns the canonical modular value at `(row, column)`.
    pub fn get(&self, row: usize, column: usize) -> i64 {
        assert!(row < self.rows, "row index out of bounds");
        assert!(column < self.columns, "column index out of bounds");
        self.values[row * self.columns + column]
    }
}

/// Generates a secret key and public key for LWE encryption.
///
/// The secret key s is a random vector in Z_q^n.
/// The public key consists of a random matrix A and a vector b = A*s + e,
/// where e is a noise vector drawn from the error distribution chi.
///
/// Returns `(secret_key, matrix_a, public_b)`.
pub fn generate_keypair(params: &LweParameters) -> (ModVector, ModMatrix, ModVector) {
    let mut rng = rand::thread_rng();

    // Secret key: random vector s in Z_q^n
    let secret_values: Vec<i64> = (0..params.dimension)
        .map(|_| rng.gen_range(0..params.modulus))
        .collect();
    let secret_key = ModVector::new(secret_values, params.modulus);

    // Public key: random matrix A and vector b = A*s + e
    let a_values: Vec<i64> = (0..params.dimension * params.sample_count)
        .map(|_| rng.gen_range(0..params.modulus))
        .collect();
    let matrix_a = ModMatrix::new(
        params.sample_count,
        params.dimension,
        a_values,
        params.modulus,
    );

    let mut b_values = Vec::with_capacity(params.sample_count);
    for row in 0..params.sample_count {
        let row_values: Vec<i64> = (0..params.dimension)
            .map(|col| matrix_a.get(row, col))
            .collect();
        let a_row = ModVector::new(row_values, params.modulus);
        let e_i = chi(params.sigma, params.modulus);
        let b_i = (a_row.dot(&secret_key) + e_i) % params.modulus;
        b_values.push(b_i);
    }
    let public_b = ModVector::new(b_values, params.modulus);

    (secret_key, matrix_a, public_b)
}

/// Encrypts a single bit using the LWE public key.
///
/// Selects a random binary vector r in {0,1}^m and computes the ciphertext
/// as (c1, c2) where:
///
///   c1 = sum(r[i] * a_i)
///   c2 = message_bit * (q/2) + sum(r[i] * b_i)   (mod q)
///
/// Returns `(c1, c2)` where c1 is a vector and c2 is a scalar.
pub fn encrypt_bit(
    message_bit: i64,
    matrix_a: &ModMatrix,
    public_b: &ModVector,
    params: &LweParameters,
) -> (ModVector, i64) {
    let mut rng = rand::thread_rng();

    // Random binary vector r in {0,1}^m
    let r: Vec<i64> = (0..params.sample_count)
        .map(|_| rng.gen_range(0..2))
        .collect();

    // c1 = sum(r[i] * a_i)
    let mut c1_values = vec![0_i64; params.dimension];
    let mut sum_bi: i64 = 0;

    for (i, ri) in r.iter().enumerate().take(params.sample_count) {
        if *ri == 1 {
            for (col, val) in c1_values.iter_mut().enumerate().take(params.dimension) {
                *val += matrix_a.get(i, col);
            }
            sum_bi += public_b.get(i);
        }
    }
    let c1 = ModVector::new(c1_values, params.modulus);

    // c2 = message_bit * (q/2) + sum(r[i] * b_i)   (mod q)
    let c2 = (message_bit * (params.modulus / 2) + sum_bi) % params.modulus;

    (c1, c2)
}

/// Decrypts an LWE ciphertext using the secret key.
///
/// Computes `c2 - c1 * s (mod q)` and compares the result to q/4 and 3*q/4.
/// Returns the decrypted message bit (0 or 1).
///
/// The decision rule is:
/// - If `decrypted` is close to 0 or close to q (below q/4 or above 3q/4), the
///   bit was 0.
/// - Otherwise the bit was 1 (encoded as q/2).
pub fn decrypt_bit(c1: &ModVector, c2: i64, secret_key: &ModVector, modulus: i64) -> i64 {
    let dot = c1.dot(secret_key);
    let decrypted = (c2 - dot).rem_euclid(modulus);

    if decrypted > modulus / 4 && decrypted < 3 * modulus / 4 {
        1
    } else {
        0
    }
}

/// Encrypts an arbitrary-length message using the LWE public key.
///
/// Each character is converted to 8 bits, and every bit is encrypted
/// independently with the single-bit `encrypt_bit` function.
///
/// Returns a vector of ciphertext pairs, one per plaintext bit.
pub fn encrypt(
    message: &str,
    matrix_a: &ModMatrix,
    public_b: &ModVector,
    params: &LweParameters,
) -> Vec<(ModVector, i64)> {
    message
        .bytes()
        .flat_map(|byte| (0..8).map(move |i| (byte >> i) & 1))
        .map(|bit| encrypt_bit(bit as i64, matrix_a, public_b, params))
        .collect()
}

/// Decrypts an arbitrary-length message from LWE ciphertexts.
///
/// The ciphertexts are grouped in blocks of 8 (one per byte), each bit
/// is decrypted with `decrypt_bit`, and the resulting bytes are assembled
/// back into a `String`.
pub fn decrypt(ciphertexts: &[(ModVector, i64)], secret_key: &ModVector, modulus: i64) -> String {
    ciphertexts
        .chunks(8)
        .map(|chunk| {
            let mut byte = 0u8;
            for (i, (c1, c2)) in chunk.iter().enumerate() {
                let bit = decrypt_bit(c1, *c2, secret_key, modulus);
                byte |= (bit as u8) << i;
            }
            byte as char
        })
        .collect()
}
