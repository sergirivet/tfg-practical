"""
Client implementation for Hybrid Post-Quantum Authenticated Handshake Protocol (3.4)

This module provides the Client class which encapsulates:
- PHASE 1: Ephemeral key generation
- PHASE 3: Dual signature verification (classical ECDSA + post-quantum Dilithium)
- PHASE 4: Shared secret computation and hybrid session key derivation
"""

from primitives.kem.classical import dh_keygen, dh_shared_secret
from primitives.kem.quantum import kyber_keygen, kyber_encapsulate
from .hybrid_handshake import client_verify_handshake, hybrid_session_key, AuthenticationError


class Client:
    """Client implementation for hybrid authenticated handshake protocol.
    
    Encapsulates all client-side operations:
    1. Generate ephemeral keys (PHASE 1)
    2. Send ephemeral public keys to server
    3. Receive server response and verify DUAL signatures (PHASE 3)
    4. Compute shared secrets and derive session key (PHASE 4)
    
    Features defense-in-depth authentication with both classical (ECDSA) and
    post-quantum (Dilithium) signature schemes.
    
    Attributes:
        server_trust_key_dilithium (bytes): Server's long-term ML-DSA signing public key
                                            (obtained through trusted channel)
        server_trust_key_ecdsa (bytes): Server's long-term ECDSA signing public key
                                        (obtained through trusted channel)
        session_key (bytes): Derived 32-byte hybrid session key (set after handshake)
    """
    
    def __init__(self, server_signing_public_key_dilithium, server_signing_public_key_ecdsa):
        """Initialize client with server's trusted public signing keys (both classical and PQ).
        
        Args:
            server_signing_public_key_dilithium (bytes): Server's long-term ML-DSA-44 public key.
                                                        Must be obtained from trusted source
                                                        (e.g., PKI certificate).
            server_signing_public_key_ecdsa (bytes): Server's long-term ECDSA public key.
                                                     Must be obtained from trusted source
                                                     (e.g., PKI certificate).
        
        Raises:
            ValueError: If either key is None or empty
        """
        if not server_signing_public_key_dilithium:
            raise ValueError("Server Dilithium signing public key cannot be None or empty")
        if not server_signing_public_key_ecdsa:
            raise ValueError("Server ECDSA signing public key cannot be None or empty")
        
        self.server_trust_key_dilithium = server_signing_public_key_dilithium
        self.server_trust_key_ecdsa = server_signing_public_key_ecdsa
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
    
    def phase3_verify_phase4_derive(self, server_pk_dh, server_pk_kyber, 
                                    server_signature_dilithium, server_signature_ecdsa):
        """PHASE 3-4: Verify DUAL signatures and derive session key.
        
        This function performs:
        1. PHASE 3: Reconstruct handshake transcript and verify BOTH signatures
                   (classical ECDSA + post-quantum Dilithium) against server's
                   long-term public keys. BOTH must verify for authentication to succeed.
        2. PHASE 4: If both signatures verify, compute shared secrets and derive
                   the hybrid session key
        
        Args:
            server_pk_dh (bytes): Server's ephemeral X25519 public key
            server_pk_kyber (bytes): Server's ephemeral ML-KEM-512 public key
            server_signature_dilithium (bytes): ML-DSA-44 signature over handshake transcript
            server_signature_ecdsa (bytes): ECDSA P-256 signature over handshake transcript
        
        Returns:
            tuple: (session_key: bytes, kyber_ciphertext: bytes)
                   32-byte hybrid session key
                   1088-byte Kyber ciphertext (needed by server to decapsulate)
        
        Raises:
            AuthenticationError: If either signature verification fails
                                (indicates possible MITM attack; handshake aborted)
        
        Security Properties:
            - Forward Secrecy: Uses ephemeral keys; compromise of long-term keys
                             does not affect past sessions
            - Dual Authentication: Both classical and PQ signatures must verify
            - Defense-in-Depth: If one signature scheme is broken, the other remains secure
            - Integrity: Transcript binding prevents key substitution attacks
        """
        
        # PHASE 3: Verify BOTH signatures (classical + post-quantum)
        # This MUST succeed for both schemes before we use any derived secrets
        client_verify_handshake(
            self.server_trust_key_dilithium,
            self.server_trust_key_ecdsa,
            self._pk_dh, self._pk_kyber,
            server_pk_dh, server_pk_kyber,
            server_signature_dilithium, server_signature_ecdsa
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
