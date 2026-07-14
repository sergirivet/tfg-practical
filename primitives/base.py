"""Abstract cryptographic interfaces used by the protocol layer.

These interfaces define the stable contract between the protocol state machine
and any concrete cryptographic implementation. The protocol only depends on
these abstractions, which lets algorithm choices change without rewriting the
handshake logic.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Tuple


def pack_length_prefixed(*parts: bytes) -> bytes:
    """Pack byte strings into a canonical length-prefixed blob."""
    return b"".join(len(part).to_bytes(4, "big") + part for part in parts)


def unpack_length_prefixed(blob: bytes, expected_parts: int) -> Tuple[bytes, ...]:
    """Unpack a canonical length-prefixed blob into its original components."""
    parts = []
    offset = 0

    for _ in range(expected_parts):
        if offset + 4 > len(blob):
            raise ValueError("Packed blob is truncated")

        part_length = int.from_bytes(blob[offset : offset + 4], "big")
        offset += 4

        if offset + part_length > len(blob):
            raise ValueError("Packed blob is truncated")

        parts.append(blob[offset : offset + part_length])
        offset += part_length

    if offset != len(blob):
        raise ValueError("Packed blob contains trailing data")

    return tuple(parts)


class KEM(ABC):
    """Abstract interface for key encapsulation and decapsulation engines."""

    @abstractmethod
    def keygen(self) -> Tuple[bytes, bytes]:
        """Return ``(secret_key, public_key)``."""

    @abstractmethod
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Return ``(shared_secret, ciphertext)`` for a peer public key."""

    @abstractmethod
    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Return the shared secret derived from a secret key and ciphertext."""


class SignatureScheme(ABC):
    """Abstract interface for signing and verification engines."""

    @abstractmethod
    def keygen(self) -> Tuple[bytes, bytes]:
        """Return ``(private_key, public_key)``."""

    @abstractmethod
    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """Return a signature for ``message``."""

    @abstractmethod
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Return ``True`` when the signature validates."""