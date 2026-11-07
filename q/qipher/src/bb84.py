"""Educational BB84 key exchange in one process.

Alice prepares qubits, Bob measures them in randomly chosen bases, and both
sift their results. The Qiskit circuit stands in for a quantum channel; this
module does not exchange qubits between two networked computers.
"""

import secrets

from qiskit import QuantumCircuit
from qiskit.providers.basic_provider import BasicSimulator


def exchange_key(key_bits: int, backend) -> tuple[bytes, bytes]:
    """Return Alice's and Bob's matching keys, each with *key_bits* bits.

    Public basis comparison discards mismatched positions. A random sample of
    matching bits is revealed to check for errors and is never used as key.
    Requests must be whole bytes, as required by the QOTP.
    """
    if key_bits < 0 or key_bits % 8:
        raise ValueError("key length must be a nonnegative multiple of 8 bits")
    if key_bits == 0:
        return b"", b""

    alice_key: list[int] = []
    bob_key: list[int] = []
    is_simulator = isinstance(backend, BasicSimulator)

    # Each batch prepares independent qubits, so a single circuit never needs
    # more than eight qubits on either a simulator or an IBM backend.
    while len(alice_key) < key_bits:
        remaining = key_bits - len(alice_key)
        n_qubits = 3 * remaining + 16  # ~half survive sifting; reserve check bits
        circuits = []
        choices = []
        for start in range(0, n_qubits, 8):
            count = min(8, n_qubits - start)
            alice_bits = [secrets.randbelow(2) for _ in range(count)]
            alice_bases = [secrets.randbelow(2) for _ in range(count)]
            bob_bases = [secrets.randbelow(2) for _ in range(count)]
            qc = QuantumCircuit(count, count)
            for i in range(count):
                if alice_bits[i]:
                    qc.x(i)
                if alice_bases[i]:
                    qc.h(i)
                if bob_bases[i]:
                    qc.h(i)
            qc.measure(range(count), range(count))
            circuits.append(qc)
            choices.append((alice_bits, alice_bases, bob_bases))

        if is_simulator:
            result = backend.run(circuits, shots=1).result()
            outcomes = [next(iter(result.get_counts(i))) for i in range(len(circuits))]
        else:
            from qiskit.compiler import transpile
            from qiskit_ibm_runtime import SamplerV2 as Sampler

            circuits = transpile(circuits, backend=backend)
            result = Sampler(mode=backend).run(circuits, shots=1).result()
            outcomes = [
                next(iter(result[i].data[qc.cregs[0].name].get_counts()))
                for i, qc in enumerate(circuits)
            ]

        matched_alice: list[int] = []
        matched_bob: list[int] = []
        for (alice_bits, alice_bases, bob_bases), outcome in zip(choices, outcomes):
            # Qiskit prints the highest-numbered classical bit first.
            for bit, a, b, measured in zip(
                alice_bits, alice_bases, bob_bases, reversed(outcome)
            ):
                if a == b:
                    matched_alice.append(bit)
                    matched_bob.append(int(measured))
        if not matched_alice:
            continue

        # The disclosed sample is removed even when every checked bit agrees.
        sample_size = min(32, max(1, len(matched_alice) // 8))
        sample = set(
            secrets.SystemRandom().sample(range(len(matched_alice)), sample_size)
        )
        errors = sum(matched_alice[i] != matched_bob[i] for i in sample)
        if errors / sample_size > 0.11:
            raise RuntimeError(
                "BB84 check failed: Alice and Bob measured different bits"
            )
        for i, (a, b) in enumerate(zip(matched_alice, matched_bob)):
            if i not in sample:
                alice_key.append(a)
                bob_key.append(b)

    if alice_key[:key_bits] != bob_key[:key_bits]:
        raise RuntimeError("BB84 keys disagree after sifting")

    def pack(bits: list[int]) -> bytes:
        return bytes(
            sum(
                bit << (7 - offset)
                for offset, bit in enumerate(bits[start : start + 8])
            )
            for start in range(0, key_bits, 8)
        )

    return pack(alice_key), pack(bob_key)
