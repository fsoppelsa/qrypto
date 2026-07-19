use pqc::lwe_encryption::{decrypt, encrypt, generate_keypair, LweParameters};

fn main() {
    let params = LweParameters::default();
    println!(
        "Sample params: n={}, q={}, samples={}, sigma={}",
        params.dimension, params.modulus, params.sample_count, params.sigma
    );

    // Alice generates her key pair.
    let (secret_key, matrix_a, public_b) = generate_keypair(&params);

    println!("Alice's secret key:");
    println!(
        "  s = [{}]",
        (0..secret_key.len())
            .map(|i| format!("{}", secret_key.get(i)))
            .collect::<Vec<_>>()
            .join(", ")
    );

    println!();
    println!("Alice's public key (A, b):");
    println!(
        "  A = ({} x {} matrix)",
        params.sample_count, params.dimension
    );
    for row in 0..params.sample_count {
        print!("    [");
        for col in 0..params.dimension {
            if col > 0 {
                print!(" ");
            }
            print!("{:3}", matrix_a.get(row, col));
        }
        println!("]");
    }
    println!(
        "  b = [{}]",
        (0..public_b.len())
            .map(|i| format!("{}", public_b.get(i)))
            .collect::<Vec<_>>()
            .join(", ")
    );

    // Bob encrypts a multi-character message.
    let bob_message = "attack at dawn";
    let ciphertexts = encrypt(bob_message, &matrix_a, &public_b, &params);

    println!();
    println!(
        "Bob encrypts: [{}]  ({} chars = {} bits)",
        bob_message,
        bob_message.len(),
        ciphertexts.len()
    );

    // Alice decrypts using her secret key.
    let alice_message = decrypt(&ciphertexts, &secret_key, params.modulus);

    println!();
    println!("Alice decrypts: [{}]", alice_message);
    println!(
        "Message: {}",
        if alice_message == bob_message {
            "DECRYPTED!"
        } else {
            "FAILED!"
        }
    );
}
