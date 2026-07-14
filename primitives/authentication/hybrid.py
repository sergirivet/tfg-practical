"""Hybrid signature engine that composes classical and post-quantum schemes."""

from __future__ import annotations

from primitives.base import SignatureScheme, pack_length_prefixed, unpack_length_prefixed

from .classical import ECDSAP256Engine
from .quantum import MLDSA44Engine


class HybridSignatureEngine(SignatureScheme):
    """Composite signature engine for defense-in-depth authentication."""

    def __init__(self, classical_engine: SignatureScheme | None = None, quantum_engine: SignatureScheme | None = None):
        self.classical_engine = classical_engine or ECDSAP256Engine()
        self.quantum_engine = quantum_engine or MLDSA44Engine()

    def keygen(self):
        classical_private, classical_public = self.classical_engine.keygen()
        quantum_private, quantum_public = self.quantum_engine.keygen()
        private_key = pack_length_prefixed(classical_private, quantum_private)
        public_key = pack_length_prefixed(classical_public, quantum_public)
        return private_key, public_key

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        classical_private, quantum_private = unpack_length_prefixed(private_key, 2)
        classical_signature = self.classical_engine.sign(classical_private, message)
        quantum_signature = self.quantum_engine.sign(quantum_private, message)
        return pack_length_prefixed(classical_signature, quantum_signature)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        try:
            classical_public, quantum_public = unpack_length_prefixed(public_key, 2)
            classical_signature, quantum_signature = unpack_length_prefixed(signature, 2)
        except ValueError:
            return False

        return (
            self.classical_engine.verify(classical_public, message, classical_signature)
            and self.quantum_engine.verify(quantum_public, message, quantum_signature)
        )