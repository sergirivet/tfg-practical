"""Client state machine for the authenticated hybrid handshake.

The client is intentionally algorithm-agnostic. It only sees opaque key blobs,
opaque ciphertext blobs, and abstract engine calls. Concrete algorithms are
selected at construction time through dependency injection.
"""

from __future__ import annotations

from primitives.base import KEM, SignatureScheme, pack_length_prefixed

from .hybrid_handshake import AuthenticationError
from .record_layer import RecordSession, RecordClosedError


def _build_handshake_transcript(client_public_key: bytes, server_ciphertext: bytes) -> bytes:
    """Build the canonical transcript over the two handshake messages."""
    return pack_length_prefixed(client_public_key, server_ciphertext)


class Client:
    """Client-side state machine for the injected-engine handshake."""

    def __init__(self, server_signing_public_key: bytes, kem_engine: KEM, signature_engine: SignatureScheme):
        if not server_signing_public_key:
            raise ValueError("Server signing public key cannot be None or empty")
        if kem_engine is None:
            raise ValueError("KEM engine cannot be None")
        if signature_engine is None:
            raise ValueError("Signature engine cannot be None")

        self.server_signing_public_key = server_signing_public_key
        self.kem_engine = kem_engine
        self.signature_engine = signature_engine
        self.session_key = None
        self.record_session = None
        self._secret_key = None
        self._public_key = None

    def phase1_generate_ephemeral_keys(self):
        """Generate the opaque client hello blob for the handshake."""
        self._secret_key, self._public_key = self.kem_engine.keygen()
        return self._public_key

    def phase3_verify_phase4_derive(self, server_ciphertext: bytes, server_signature: bytes):
        """Verify the server response and derive the session key."""
        if self._secret_key is None or self._public_key is None:
            raise RuntimeError("Phase 1 must complete before verification")

        transcript = _build_handshake_transcript(self._public_key, server_ciphertext)

        if not self.signature_engine.verify(self.server_signing_public_key, transcript, server_signature):
            raise AuthenticationError(
                "Handshake authentication failed: server signature verification failed. Handshake aborted."
            )

        self.session_key = self.kem_engine.decapsulate(self._secret_key, server_ciphertext)
        self.record_session = RecordSession(master_secret=self.session_key, is_server=False)
        return self.session_key

    def send_application_data(self, plaintext: bytes) -> bytes:
        """Seal application data for the peer using the active record session."""
        if self.record_session is None:
            raise RuntimeError("Record session is not available; handshake has not completed")

        return self.record_session.seal_record(0x17, plaintext)

    def receive_application_data(self, record_frame: bytes) -> bytes:
        """Open an incoming application record and return plaintext bytes."""
        if self.record_session is None:
            raise RuntimeError("Record session is not available; handshake has not completed")

        return self.record_session.open_record(record_frame)

    def close_session(self) -> bytes:
        """Create an encrypted close_notify alert for clean shutdown."""
        if self.record_session is None:
            raise RuntimeError("Record session is not available; handshake has not completed")

        return self.record_session.seal_record(0x15, b"\x01\x00")
    
    def get_session_key(self):
        """Get the derived session key.
        
        Returns:
            bytes: 32-byte hybrid session key, or None if handshake not complete
        
        Raises:
            RuntimeError: If handshake not completed (session_key is None)
        """
        if self.session_key is None:
            raise RuntimeError("Handshake not yet completed; session key not available")
        return self.session_key
