"""Concrete Dilithium/ML-DSA-44 signature adapter."""

from __future__ import annotations

from typing import Tuple

from dilithium_py.ml_dsa import ML_DSA_44

from primitives.base import SignatureScheme


class MLDSA44Engine(SignatureScheme):
    """Concrete signature adapter for ML-DSA-44 / Dilithium."""

    def keygen(self) -> Tuple[bytes, bytes]:
        public_key, private_key = ML_DSA_44.keygen()
        return private_key, public_key

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        return ML_DSA_44.sign(private_key, message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        try:
            return ML_DSA_44.verify(public_key, message, signature)
        except Exception:
            return False
