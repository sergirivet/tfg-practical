"""Server state machine for the authenticated hybrid handshake."""

from __future__ import annotations

from primitives.base import KEM, SignatureScheme, pack_length_prefixed

from .record_layer import RecordSession


def _build_handshake_transcript(client_public_key: bytes, server_ciphertext: bytes) -> bytes:
    """Build the canonical transcript over the two handshake messages."""
    return pack_length_prefixed(client_public_key, server_ciphertext)


class Server:
    """Server-side state machine for the injected-engine handshake."""

    def __init__(self, signing_private_key: bytes, kem_engine: KEM, signature_engine: SignatureScheme):
        if not signing_private_key:
            raise ValueError("Signing private key cannot be None or empty")
        if kem_engine is None:
            raise ValueError("KEM engine cannot be None")
        if signature_engine is None:
            raise ValueError("Signature engine cannot be None")

        self.signing_private_key = signing_private_key
        self.kem_engine = kem_engine
        self.signature_engine = signature_engine
        self.session_key = None
        self.record_session = None

    def phase2_generate_ephemeral_and_sign(self, client_public_key: bytes):
        """Generate the server hello blob and sign the handshake transcript."""
        self.session_key, server_ciphertext = self.kem_engine.encapsulate(client_public_key)
        transcript = _build_handshake_transcript(client_public_key, server_ciphertext)
        signature = self.signature_engine.sign(self.signing_private_key, transcript)
        return server_ciphertext, signature

    def phase4_derive_session_key(self, client_public_key: bytes | None = None):
        """Finalize the record session using the key established in phase 2."""
        if self.session_key is None:
            raise RuntimeError("Session key not available; PHASE 2 must complete first")

        self.record_session = RecordSession(master_secret=self.session_key, is_server=True)
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
