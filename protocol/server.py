"""
Server implementation for Hybrid Post-Quantum Authenticated Handshake Protocol (3.4)

This module provides the Server class which encapsulates:
- PHASE 0: Long-term signing key setup (one-time, both classical and PQ)
- PHASE 2: Ephemeral key generation and dual signature creation (ECDSA + Dilithium)
- PHASE 4: Shared secret computation and hybrid session key derivation
"""

from primitives.kem.classical import dh_keygen, dh_shared_secret
from primitives.kem.quantum import kyber_encapsulate
from .record_layer import RecordSession
from .hybrid_handshake import server_sign_handshake, hybrid_session_key


class Server:
    """Server implementation for hybrid authenticated handshake protocol.
    
    Encapsulates all server-side operations:
    0. Initialize with long-term signing keys (done once, reused across sessions)
       - Both classical (ECDSA) and post-quantum (Dilithium) keys for defense-in-depth
    1. Generate ephemeral keys and sign handshake transcript with both schemes (PHASE 2)
    2. Compute shared secrets and derive session key (PHASE 4)
    
    Attributes:
        sk_sign_dilithium (bytes): Server's long-term ML-DSA-44 private signing key (secret)
        sk_sign_ecdsa (bytes): Server's long-term ECDSA private signing key (secret)
        session_key (bytes): Derived 32-byte hybrid session key (set after handshake)
    """
    
    def __init__(self, signing_private_key_dilithium, signing_private_key_ecdsa):
        """Initialize server with long-term signing keys (both classical and PQ).
        
        Args:
            signing_private_key_dilithium (bytes): Server's long-term ML-DSA-44 private key.
                                                  Must be kept secret and used to sign all
                                                  handshake transcripts (PQ authentication).
            signing_private_key_ecdsa (bytes): Server's long-term ECDSA private key.
                                              Must be kept secret and used to sign all
                                              handshake transcripts (classical authentication).
        
        Raises:
            ValueError: If either key is None or empty
        """
        if not signing_private_key_dilithium:
            raise ValueError("Dilithium signing private key cannot be None or empty")
        if not signing_private_key_ecdsa:
            raise ValueError("ECDSA signing private key cannot be None or empty")
        
        self.sk_sign_dilithium = signing_private_key_dilithium
        self.sk_sign_ecdsa = signing_private_key_ecdsa
        self.session_key = None
        self.record_session = None
        
        # Ephemeral keys (set in phase2)
        self._sk_dh = None
        self._pk_dh = None
        self._ss_kyber = None
    
    def phase2_generate_ephemeral_and_sign(self, client_pk_dh, client_pk_kyber):
        """PHASE 2: Generate ephemeral DH key, encapsulate to client Kyber key, and sign.
        
        Server generates a fresh ephemeral DH key for this session, encapsulates
        a Kyber shared secret to the client's public key, and creates DUAL
        signatures (ECDSA + Dilithium) over the handshake transcript.
        These signatures prove the server's identity through both classical
        and post-quantum authentication, providing defense-in-depth.
        
        Args:
            client_pk_dh (bytes): Client's ephemeral X25519 public key
                                 (received in PHASE 1)
            client_pk_kyber (bytes): Client's ephemeral ML-KEM-512 public key
                                    (received in PHASE 1)
        
        Returns:
                 tuple: (pk_dh: bytes, kyber_ciphertext: bytes, sig_dilithium: bytes, sig_ecdsa: bytes)
                   Server's ephemeral X25519 public key (32 bytes)
                     Kyber ciphertext for the client (1088 bytes)
                   ML-DSA-44 signature over handshake transcript (~2420 bytes)
                   ECDSA P-256 signature over handshake transcript (~71 bytes)
        
        Security Note:
            Uses length-prefixing to prevent ambiguity attacks on transcript boundaries:
            transcript = LP(client_pk_dh) || LP(client_pk_kyber) || 
                        LP(server_pk_dh) || LP(kyber_ciphertext)
            where LP(x) = len(x) as 4-byte big-endian || x
            
            BOTH signatures must verify for successful authentication.
        """
        
        # Generate ephemeral X25519 key pair
        self._sk_dh, self._pk_dh = dh_keygen()
        
        # Encapsulate to the client's Kyber public key; server keeps the resulting shared secret
        kyber_ciphertext, self._ss_kyber = kyber_encapsulate(client_pk_kyber)
        
        # Sign the handshake transcript with BOTH classical and PQ schemes
        sig_dilithium, sig_ecdsa = server_sign_handshake(
            self.sk_sign_dilithium,
            self.sk_sign_ecdsa,
            client_pk_dh, client_pk_kyber,
            self._pk_dh, kyber_ciphertext
        )
        
        return self._pk_dh, kyber_ciphertext, sig_dilithium, sig_ecdsa
    
    def phase4_derive_session_key(self, client_pk_dh):
        """PHASE 4: Compute shared secrets and derive hybrid session key.
        
        Server receives the client's ephemeral DH public key, then computes:
        1. DH shared secret using client's ephemeral public and server's ephemeral private
        2. Kyber shared secret from the encapsulation performed in PHASE 2
        3. Hybrid session key by combining both secrets through HKDF
        
        Args:
            client_pk_dh (bytes): Client's ephemeral X25519 public key
                                 (used as DH peer in scalar multiplication)
        Returns:
            bytes: 32-byte hybrid session key
        
        Security Properties:
            - Forward Secrecy: Session key depends only on ephemeral keys;
                             compromise of long-term signing key does NOT
                             compromise past sessions
            - Post-Quantum Security: ML-KEM-512 (IND-CCA2 secure) ensures security
                                   even if quantum computers break X25519
            - Hybrid Strength: Both DH and Kyber must fail for session to be broken
        """
        
        # DH shared secret: server's ephemeral private × client's ephemeral public
        ss_dh = dh_shared_secret(self._sk_dh, client_pk_dh)
        
        # Kyber shared secret: reuse encapsulation result from PHASE 2
        if self._ss_kyber is None:
            raise RuntimeError("Kyber shared secret not available; PHASE 2 must complete first")
        ss_kyber = self._ss_kyber
        
        # Derive hybrid session key by combining both secrets
        self.session_key = hybrid_session_key(ss_dh, ss_kyber)
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
