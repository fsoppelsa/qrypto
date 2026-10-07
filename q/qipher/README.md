# qipher

A quantum one-time pad (QOTP) chat toy, runs on real IBM Quantum hardware.

## Quantum Vernam

Each plaintext byte is encoded into 8 qubits, $|0\rangle$ or $|1\rangle$. 

Alice encrypts applying a random Pauli mask per qubit, using 2 key bits $(k_1, k_2)$:

$$E_{k_1,k_2}(\rho) = X^{k_1} Z^{k_2}\, \rho\, Z^{k_2} X^{k_1}$$

Bob decrypts applying the inverse and in reverse order:

$$D_{k_1,k_2}(\rho) = Z^{k_2} X^{k_1}\, \rho\, X^{k_1} Z^{k_2}$$

Since $X^2 = Z^2 = I$, $D_{k_1,k_2} \circ E_{k_1,k_2} = I$: applying the same key twice recovers $\rho$ exactly. With $(k_1,k_2)$ uniform and secret, the encrypted state is maximally mixed to Eve like a quantum analogue of the classical Vernam.
For an $n$-bit message, the key is $2n$ bits, one $(k_1,k_2)$ pair per qubit, never reused.

## Key generation and sharing (educational only)

For each message of $n$ bytes, the sender creates a fresh $2n$-byte key.
Without `QISKIT_IBM_TOKEN`, the key comes from Python's `secrets` generator.
With an IBM Quantum token, an eight-qubit Hadamard-and-measure circuit runs
for $2n$ shots on a QPU to produce the key; failure aborts the send rather
than silently substituting simulated randomness. Set `QISKIT_IBM_BACKEND`
to choose a backend, or let the program choose an available QPU.

The message frame contains its length, **the raw key**, and the ciphertext.
The receiver uses the key once and drops its Python reference. The CLI's
“Trashing OTP key” message does **not** mean secure memory erasure.
Sending the key in cleartext makes this chat **not private**; this is only
an exercise until authenticated key distribution (e.g. BB84) is implemented.

## Hardware

Circuits run on IBM Quantum backends (e.g. `ibm_marrakesh` or `ibm_fez`) via Qiskit Runtime when configured. The following screenshots illustrate an earlier QPU run, not a performance guarantee:

![IBM Quantum job analytics](img/ibm_analytics.png)

Two peers exchanging an encrypted message end-to-end (**erwin** encrypts, **albert** decrypts), each round-tripping through `ibm_fez`:

![Chat session encrypting and decrypting over IBM Quantum](img/flow.png)
