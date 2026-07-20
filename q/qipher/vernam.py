"""
Quantum One-Time Pad

The Quantum One-Time Pad encrypts an n-qubit state by applying a Pauli
operator X^{k1} Z^{k2} to each qubit individually, where (k1, k2) are
key bits.  Decryption applies the inverse Z^{k2} X^{k1}.

This module implements QOTP over classical messages: each message byte
is turned into 8 qubits (|0⟩ or |1⟩), encrypted, then decrypted and measured.

Key: For a 5-byte (40-bit) message it needs 80 key bits = 10 bytes
(2 key bits per qubit).  The fixed key ``KEY`` is derived from the original
5-byte XOR key by concatenating it with itself.

Backend:
* IBM Quantum QPU if the environment variable QISKIT_IBM_TOKEN is
  set, a real IBM Quantum backend is used
* Local simulator falls back to BasicSimulator otherwise.
"""

from __future__ import annotations

import os

import numpy as _numpy

_original_array = _numpy.array


def _patched_array(*args, **kwargs):
    if "copy" in kwargs and kwargs["copy"] is None:
        kwargs["copy"] = False
    return _original_array(*args, **kwargs)


_numpy.array = _patched_array
# ────────────────────────────────────────────────────────────────────────────

# ── Suppress qiskit-ibm-runtime informational warnings ──────────────────────
import logging

os.environ.setdefault("QISKIT_IBM_RUNTIME_LOG_LEVEL", "ERROR")

_logger = logging.getLogger("qiskit_runtime_service")
_logger.setLevel(logging.ERROR)
_logger.propagate = False

_logger = logging.getLogger("qiskit_ibm_runtime")
_logger.setLevel(logging.ERROR)
_logger.propagate = False

from qiskit import QuantumCircuit

# Our fixed key: 10 bytes = 80 bits (enough for 40 qubits / 5 message bytes)
KEY = bytes([0x5A, 0x3C, 0x7E, 0x1F, 0x9B, 0x5A, 0x3C, 0x7E, 0x1F, 0x9B])

_MAX_MSG_BYTES = 5


# ── Backend selection ────────────────────────────────────────────────────────
# Set QISKIT_IBM_TOKEN to run on a real IBM Quantum backend.


def _get_backend():
    """Return a Qiskit backend (IBM Quantum if configured, else BasicSimulator)."""
    token = os.environ.get("QISKIT_IBM_TOKEN")
    if token:
        try:
            from qiskit_ibm_runtime import QiskitRuntimeService

            service = QiskitRuntimeService(channel="ibm_quantum_platform", token=token)
            backend_name = os.environ.get("QISKIT_IBM_BACKEND")
            if backend_name:
                backend = service.backend(backend_name)
            else:
                backend = service.least_busy(
                    simulator=False,
                    operational=True,
                    min_num_qubits=1,
                )
            print(f"[qotp] IBM Quantum backend: {backend.name}")
            return backend
        except ImportError:
            print(
                "[qotp] qiskit-ibm-runtime not installed, "
                "falling back to BasicSimulator"
            )
        except Exception as exc:
            print(
                f"[qotp] IBM Quantum unavailable ({exc}), "
                "falling back to BasicSimulator"
            )

    from qiskit.providers.basic_provider import BasicSimulator

    return BasicSimulator()


def _run_circuit(qc: QuantumCircuit, *, shots: int = 1) -> str:
    """Run *qc* (which must include measurements) and return the bitstring.

    The bitstring is in Qiskit's convention (MSB corresponds to qubit n-1).
    """
    backend = _get_backend()
    from qiskit.providers.basic_provider import BasicSimulator

    if isinstance(backend, BasicSimulator):
        job = backend.run(qc, shots=shots)
        counts = job.result().get_counts(qc)
    else:
        # IBM Quantum backend — transpile and use SamplerV2 primitive
        from qiskit.compiler import transpile
        from qiskit_ibm_runtime import SamplerV2 as Sampler

        qc = transpile(qc, backend=backend)
        sampler = Sampler(mode=backend)
        job = sampler.run([qc], shots=shots)
        result = job.result()
        creg_name = qc.cregs[0].name
        counts = result[0].data[creg_name].get_counts()

    return next(iter(counts))


def _bytes_to_bits(data: bytes) -> list[int]:
    """Convert data to a list of bits (MSB first within each byte)."""
    bits: list[int] = []
    for byte in data:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


def _bits_to_bytes(bits: list[int]) -> bytes:
    """Convert a list of bits (MSB first) back to bytes."""
    result = bytearray()
    for chunk_start in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            pos = chunk_start + j
            if pos < len(bits):
                byte |= bits[pos] << (7 - j)
        result.append(byte)
    return bytes(result)


def _get_key_pairs(key: bytes, n_pairs: int) -> list[tuple[int, int]]:
    """Extract ``(k1, k2)`` pairs from key for n_pairs qubits.

    Key bits are consumed MSB‑first: bit 0 of the key → k1 for qubit 0,
    bit 1 → k2 for qubit 0, bit 2 → k1 for qubit 1, etc.
    """
    key_int = int.from_bytes(key, "big")
    n_key_bits = len(key) * 8
    pairs: list[tuple[int, int]] = []
    for i in range(n_pairs):
        k1 = (key_int >> (n_key_bits - 1 - 2 * i)) & 1
        k2 = (key_int >> (n_key_bits - 1 - 2 * i - 1)) & 1
        pairs.append((k1, k2))
    return pairs


# ── Circuit builders ──


def qotp_encrypt_circuit(msg: bytes, key: bytes = KEY) -> QuantumCircuit:
    """Build a circuit that encrypts msg with the QOTP.

    The circuit allocates ``8 * len(msg)`` qubits, initialises them to the
    message bit values, then applies X^{k1} Z^{k2} per qubit.

    """
    msg_bits = _bytes_to_bits(msg)
    n = len(msg_bits)
    qc = QuantumCircuit(n, n)

    # Prepare message qubits
    for i, bit in enumerate(msg_bits):
        if bit == 1:
            qc.x(i)

    # Encrypt:  X^{k1} * Z^{k2}
    pairs = _get_key_pairs(key, n)
    for i, (k1, k2) in enumerate(pairs):
        if k2:
            qc.z(i)
        if k1:
            qc.x(i)

    return qc


def qotp_decrypt_circuit(ciphertext: bytes, key: bytes = KEY) -> QuantumCircuit:
    """Build a circuit that decrypts ciphertext with the QOTP.

    The circuit allocates ``8 * len(ciphertext)`` qubits, initialises them
    from the measured ciphertext bits, then applies the inverse Pauli
    operators Z^{k2} X^{k1} per qubit.  No measurements are added.

    Parameters
    ----------
    ciphertext:
        Ciphertext bytes (produced by :func:`qotp_encrypt`).
    key:
        10‑byte QOTP key.

    Returns
    -------
    QuantumCircuit
        Circuit with the decrypted plaintext state (no measurements).
    """
    c_bits = _bytes_to_bits(ciphertext)
    n = len(c_bits)
    pairs = _get_key_pairs(key, n)

    qc = QuantumCircuit(n, n)

    # Prepare ciphertext qubits
    for i, bit in enumerate(c_bits):
        if bit == 1:
            qc.x(i)

    # Decrypt:  Z^{k2} X^{k1}  (inverse of encrypt X^{k1} Z^{k2})
    for i, (k1, k2) in enumerate(pairs):
        if k1:
            qc.x(i)
        if k2:
            qc.z(i)

    return qc


def qotp_full_circuit(msg: bytes, key: bytes = KEY) -> QuantumCircuit:
    """Build a circuit that encrypts, decrypts and measures msg.

    This is useful for verifying correctness: the measured output should
    match the original plaintext.

    """
    msg_bits = _bytes_to_bits(msg)
    n = len(msg_bits)
    pairs = _get_key_pairs(key, n)

    qc = QuantumCircuit(n, n)

    # ── prepare message ──
    for i, bit in enumerate(msg_bits):
        if bit == 1:
            qc.x(i)

    # ── encrypt: X^{k1} Z^{k2} ──
    for i, (k1, k2) in enumerate(pairs):
        if k2:
            qc.z(i)
        if k1:
            qc.x(i)

    # ── decrypt: Z^{k2} X^{k1}  (inverse of encrypt) ──
    for i, (k1, k2) in enumerate(pairs):
        if k1:
            qc.x(i)
        if k2:
            qc.z(i)

    # ── measure ──
    qc.measure(range(n), range(n))

    return qc


# Public API


def qotp_encrypt(msg: bytes, key: bytes = KEY) -> bytes:
    """Encrypt *msg* using the QOTP and return the measured ciphertext.

    The backend is chosen automatically — see the module docstring.
    """
    qc = qotp_encrypt_circuit(msg, key)
    n = qc.num_qubits
    qc.measure(range(n), range(n))
    bitstring = _run_circuit(qc)
    # Qiskit returns measured bits MSB‑first, but the rightmost qubit
    # in the string is qubit 0.  Reverse to match our convention.
    bits = [int(c) for c in bitstring[::-1]]
    return _bits_to_bytes(bits)


def qotp_decrypt(ciphertext: bytes, key: bytes = KEY) -> bytes:
    """Decrypt ciphertext produced by :func:`qotp_encrypt`.

    Rebuilds qubits from the measured ciphertext bits and applies the
    inverse Pauli operators (Z^{k2} X^{k1}) to recover the plaintext.
    """
    qc = qotp_decrypt_circuit(ciphertext, key)
    qc.measure(range(qc.num_qubits), range(qc.num_qubits))
    bitstring = _run_circuit(qc)
    bits = [int(c) for c in bitstring[::-1]]
    return _bits_to_bytes(bits)
