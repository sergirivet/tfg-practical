"""Hybrid KEM engine that composes classical and post-quantum engines."""

from __future__ import annotations

from primitives.base import KEM, pack_length_prefixed, unpack_length_prefixed
from primitives.kdf.hkdf import hkdf_extract, hkdf_expand

from .classical import X25519Engine
from .quantum import MLKEM512Engine


def _derive_hybrid_session_key(classical_secret: bytes, quantum_secret: bytes, context: bytes = b"") -> bytes:
    """Derive a single session key from the classical and quantum secrets."""
    combined_secret = classical_secret + quantum_secret
    prk = hkdf_extract(None, combined_secret)
    info = b"hybrid handshake" + (b"|" + context if context else b"")
    return hkdf_expand(prk, info, 32)


class HybridKEMEngine(KEM):
    """Composite KEM that keeps the protocol agnostic to component schemes."""

    def __init__(self, classical_engine: KEM | None = None, quantum_engine: KEM | None = None):
        self.classical_engine = classical_engine or X25519Engine()
        self.quantum_engine = quantum_engine or MLKEM512Engine()

    def keygen(self):
        classical_secret, classical_public = self.classical_engine.keygen()
        quantum_secret, quantum_public = self.quantum_engine.keygen()
        secret_key = pack_length_prefixed(classical_secret, quantum_secret)
        public_key = pack_length_prefixed(classical_public, quantum_public)
        return secret_key, public_key

    def encapsulate(self, public_key: bytes):
        classical_public, quantum_public = unpack_length_prefixed(public_key, 2)

        classical_secret, server_classical_public = self.classical_engine.keygen()
        classical_shared_secret = self.classical_engine.decapsulate(classical_secret, classical_public)

        quantum_shared_secret, quantum_ciphertext = self.quantum_engine.encapsulate(quantum_public)
        session_key = _derive_hybrid_session_key(classical_shared_secret, quantum_shared_secret)

        ciphertext = pack_length_prefixed(server_classical_public, quantum_ciphertext)
        return session_key, ciphertext

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        classical_secret, quantum_secret = unpack_length_prefixed(secret_key, 2)
        server_classical_public, quantum_ciphertext = unpack_length_prefixed(ciphertext, 2)

        classical_shared_secret = self.classical_engine.decapsulate(classical_secret, server_classical_public)
        quantum_shared_secret = self.quantum_engine.decapsulate(quantum_secret, quantum_ciphertext)
        return _derive_hybrid_session_key(classical_shared_secret, quantum_shared_secret)