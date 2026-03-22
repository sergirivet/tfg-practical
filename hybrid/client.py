"""
Client implementation for Hybrid Post-Quantum Authenticated Handshake Protocol (3.4)

This module provides the Client class which encapsulates:
- PHASE 1: Ephemeral key generation
- PHASE 3: Server signature verification  
- PHASE 4: Shared secret computation and hybrid session key derivation
"""

from dh_kem.kem import dh_keygen, dh_shared_secret
from pq_kem.kyber_kem import kyber_keygen, kyber_encapsulate
from .hybrid_handshake import client_verify_handshake, hybrid_session_key, AuthenticationError


class Client:
    """Client implementation for hybrid authenticated handshake protocol.
    
    Encapsulates all client-side operations:
    1. Generate ephemeral keys (PHASE 1)
    2. Send ephemeral public keys to server
    3. Receive server response and verify signature (PHASE 3)
    4. Compute shared secrets and derive session key (PHASE 4)
    
    Attributes:
        server_trust_key (bytes): Server's long-term ML-DSA signing public key
                                 (obtained through trusted channel, e.g., certificate)
        session_key (bytes): Derived 32-byte hybrid session key (set after successful handshake)
    """
    
    def __init__(self, server_signing_public_key):
        """Initialize client with server's trusted public signing key.
        
        Args:
            server_signing_public_key (bytes): Server's long-term ML-DSA-44 public key.
                                             Must be obtained from trusted source.
        
        Raises:
            ValueError: If key is None or empty
        """
        if not server_signing_public_key:
            raise ValueError("Server signing public key cannot be None or empty")
        
        self.server_trust_key = server_signing_public_key
        self.session_key = None
        
        # Ephemeral keys (set in phase1)
        self._sk_dh = None
        self._pk_dh = None
        self._pk_kyber = None
        self._sk_kyber = None
    
    def phase1_generate_ephemeral_keys(self):
        """PHASE 1: Generate ephemeral DH and Kyber key pairs.
        
        Client generates fresh ephemeral keys for this session.
        These keys are short-lived and will be deleted after session establishment.
        
        Returns:
            tuple: (pk_dh: bytes, pk_kyber: bytes)
                   32-byte X25519 public key
                   1184-byte ML-KEM-512 public key
        
        Security Note:
            Private keys are stored internally and used only in PHASE 4.
            After session key derivation, private keys should be cleared.
        """
        # Generate ephemeral X25519 key pair
        self._sk_dh, self._pk_dh = dh_keygen()
        
        # Generate ephemeral Kyber/ML-KEM key pair
        self._pk_kyber, self._sk_kyber = kyber_keygen()
        
        return self._pk_dh, self._pk_kyber
    
    def phase3_verify_phase4_derive(self, server_pk_dh, server_pk_kyber, server_signature):
        """PHASE 3-4: Verify server signature and derive session key.
        
        This function performs:
        1. PHASE 3: Reconstruct handshake transcript and verify server's signature
                   against server's long-term public key
        2. PHASE 4: If verification succeeds, compute shared secrets and derive
                   the hybrid session key
        
        Args:
            server_pk_dh (bytes): Server's ephemeral X25519 public key
            server_pk_kyber (bytes): Server's ephemeral ML-KEM-512 public key
            server_signature (bytes): ML-DSA-44 signature over handshake transcript
        
        Returns:
            tuple: (session_key: bytes, kyber_ciphertext: bytes)
                   32-byte hybrid session key
                   1088-byte Kyber ciphertext (needed by server to decapsulate)
        
        Raises:
            AuthenticationError: If signature verification fails
                                (indicates possible MITM attack; handshake aborted)
        
        Security Properties:
            - Forward Secrecy: Uses ephemeral keys; compromise of long-term keys
                             does not affect past sessions
            - Authentication: Signature proves server possession of signing key
            - Integrity: Transcript binding prevents key substitution attacks
        """
        
        # PHASE 3: Verify server's signature
        # This MUST succeed before we use any derived secrets
        client_verify_handshake(
            self.server_trust_key,
            self._pk_dh, self._pk_kyber,
            server_pk_dh, server_pk_kyber,
            server_signature
        )
        
        # PHASE 4: Compute shared secrets
        
        # DH shared secret: client's ephemeral private × server's ephemeral public
        ss_dh = dh_shared_secret(self._sk_dh, server_pk_dh)
        
        # Kyber shared secret: encapsulate to server's ephemeral public key
        kyber_ct, ss_kyber = kyber_encapsulate(server_pk_kyber)
        
        # Derive hybrid session key by combining both secrets
        self.session_key = hybrid_session_key(ss_dh, ss_kyber)
        
        # Return session key and Kyber ciphertext (needed by server)
        return self.session_key, kyber_ct
    
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
