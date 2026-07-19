# Learning With Errors (LWE) — Theory and Implementation

## Overview

Learning With Errors (LWE) is a PQC primitive introduced by Oded
Regev in 2005. Its security relies on the hardness of solving noisy
linear equations over finite rings — a problem believed to be hard
even for quantum computers.

## Parameters

The LWE instance is parametrised by four values (see `LweParameters` in the code):

| Symbol | Constant      | Value | Meaning                        |
|--------|---------------|-------|--------------------------------|
| $n$    | `N`           | 8     | Dimension of the secret vector |
| $q$    | `Q`           | 127   | Prime modulus for arithmetic   |
| $m$    | `SAMPLE_COUNT`| 42    | Number of LWE samples          |
| $\sigma$ | `SIGMA`     | 1.0   | Noise standard deviation       |

The sample count $m$ is derived from Regev's recommendation:
$m = \lfloor 1.1 \cdot n \cdot \ln(q) \rfloor$.

## Key Generation

### Secret Key

Alice picks a random vector $\mathbf{s} \in \mathbb{Z}_q^n$ (uniformly from $[0, q)$).

```rust
// pqc/src/lwe_encryption.rs — generate_keypair()
let secret_values: Vec<i64> = (0..params.dimension)
    .map(|_| rng.gen_range(0..params.modulus))
    .collect();
let secret_key = ModVector::new(secret_values, params.modulus);
```

### Public Key

The public key consists of two parts:

1. **Matrix $A$**: an $m \times n$ matrix with entries chosen uniformly from $[0, q)$.
2. **Vector $\mathbf{b}$**: computed as $\mathbf{b} = A \cdot \mathbf{s} + \mathbf{e} \pmod{q}$,
   where $\mathbf{e}$ is a noise vector drawn from the error distribution $\chi$ (a discrete
   Gaussian with standard deviation $\sigma$).

$$
b_i = \mathbf{a}_i \cdot \mathbf{s} + e_i \pmod{q}
$$

```rust
// pqc/src/lwe_encryption.rs — generate_keypair()
let a_values: Vec<i64> = (0..params.dimension * params.sample_count)
    .map(|_| rng.gen_range(0..params.modulus))
    .collect();
let matrix_a = ModMatrix::new(params.sample_count, params.dimension, a_values, params.modulus);

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
```

The full function returns the triple `(secret_key, matrix_a, public_b)`.

## Encryption

To encrypt a single bit $m \in \{0, 1\}$ using the public key $(A, \mathbf{b})$:

1. Choose a random binary vector $\mathbf{r} \in \{0,1\}^m$.
2. Compute $\mathbf{c}_1 = \sum_i r_i \cdot \mathbf{a}_i$ — the subset-sum of rows of $A$ selected by $\mathbf{r}$.
3. Compute $c_2 = m \cdot \lfloor q/2 \rfloor + \sum_i r_i \cdot b_i \pmod{q}$ — the encoded bit plus the subset-sum of $\mathbf{b}$ entries.

The ciphertext is the pair $(\mathbf{c}_1, c_2)$.

```rust
// pqc/src/lwe_encryption.rs — encrypt_bit()
let r: Vec<i64> = (0..params.sample_count)
    .map(|_| rng.gen_range(0..2))
    .collect();

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
let c2 = (message_bit * (params.modulus / 2) + sum_bi) % params.modulus;
```

### Encrypting Arbitrary Messages

To encrypt a string, each character is decomposed into 8 bits. Every bit is encrypted independently using `encrypt_bit`, producing a vector of ciphertext pairs:

```rust
// pqc/src/lwe_encryption.rs — encrypt()
message
    .bytes()
    .flat_map(|byte| (0..8).map(move |i| (byte >> i) & 1))
    .map(|bit| encrypt_bit(bit as i64, matrix_a, public_b, params))
    .collect()
```

For example, `"attack at dawn"` (14 characters) produces $14 \times 8 = 112$ ciphertexts.

## Decryption

Given a ciphertext $(\mathbf{c}_1, c_2)$ and the secret key $\mathbf{s}$, Alice computes:

$$
d = c_2 - \mathbf{c}_1 \cdot \mathbf{s} \pmod{q}
$$

Substituting the encryption formulas:

$$
\begin{aligned}
d &= \bigl[m \cdot \lfloor q/2 \rfloor + \sum_i r_i \cdot b_i\bigr]
    - \bigl(\sum_i r_i \cdot \mathbf{a}_i\bigr) \cdot \mathbf{s} \pmod{q} \\[4pt]
  &= m \cdot \lfloor q/2 \rfloor
     + \sum_i r_i \cdot (\mathbf{a}_i \cdot \mathbf{s} + e_i)
     - \sum_i r_i \cdot \mathbf{a}_i \cdot \mathbf{s} \pmod{q} \\[4pt]
  &= m \cdot \lfloor q/2 \rfloor + \sum_i r_i \cdot e_i \pmod{q}
\end{aligned}
$$

The $A\mathbf{s}$ terms cancel out, leaving only the encoded message bit and the accumulated noise.

- If $m = 0$: $d = \sum_i r_i \cdot e_i$ — close to $0$ (or close to $q$ due to modular wrap-around).
- If $m = 1$: $d = \lfloor q/2 \rfloor + \sum_i r_i \cdot e_i$ — close to $q/2$.

Alice decodes with a two-sided threshold:

```rust
// pqc/src/lwe_encryption.rs — decrypt_bit()
let dot = c1.dot(secret_key);
let decrypted = (c2 - dot).rem_euclid(modulus);

if decrypted > modulus / 4 && decrypted < 3 * modulus / 4 {
    1  // near q/2
} else {
    0  // near 0 or near q
}
```

The thresholds $q/4$ and $3q/4$ tolerate noise up to $|\sum e_i| < q/4$.
With our parameters ($q = 127$, $\sigma = 1.0$, ~21 active noise terms), noise is
typically bounded by 15–20, well within the safe margin.

### Decrypting Arbitrary Messages

Ciphertexts are grouped into blocks of 8, each bit is decrypted with `decrypt_bit`,
and the resulting bytes are assembled back into a string:

```rust
// pqc/src/lwe_encryption.rs — decrypt()
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
```

## Noise Distribution

The error term $e_i$ is drawn from a discrete Gaussian distribution — the standard
normal $\mathcal{N}(0, 1)$ scaled by $\sigma$ and rounded to the nearest integer:

```rust
// pqc/src/lwe_encryption.rs — chi()
let normal = Normal::new(0.0, 1.0).expect("invalid normal distribution parameters");
let sample: f64 = rand::thread_rng().sample(normal);
(sample * stdev).round() as i64
```

The noise is **not** reduced modulo $q$; it remains a small signed value centred at zero.
Reducing modulo $q$ would wrap negative values (e.g. $-3 \to 124$) to large positive ones,
destroying the noise symmetry and breaking decryption.

## Why is secure

The public key $(A, \mathbf{b} = A\mathbf{s} + \mathbf{e})$ hides the secret $\mathbf{s}$
because recovering $\mathbf{s}$ from $(A, \mathbf{b})$ is equivalent to solving the
**LWE search problem**: given many noisy linear equations $\mathbf{a}_i \cdot \mathbf{s} + e_i \approx b_i$,
find $\mathbf{s}$. Without the noise, this is trivial (Gaussian elimination). With noise,
it is believed to be as hard as worst-case lattice problems.

The ciphertext hides the message bit because $c_2$ is masked by $\sum_i r_i \cdot b_i$,
which looks uniformly random to anyone who does not know $\mathbf{s}$.

## References

- Regev, O. (2005). *On lattices, learning with errors, random linear codes, and cryptography*. STOC 2005.
