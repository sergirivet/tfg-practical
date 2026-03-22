"""
Server implementation for Hybrid Post-Quantum Authenticated Handshake Protocol (3.4)

This module provides the Server class which encapsulates:
- PHASE 0: Long-term signing key setup (one-time)
- PHASE 2: Ephemeral key generation and signature creation
- PHASE 4: Shared secret computation and hybrid session key derivation
"""

from dh_kem.kem import dh_keygen, dh_shared_secret
from pq_kem.kyber_kem import kyber_keygen, kyber_decapsulate
from .hybrid_handshake import server_sign_handshake, hybrid_session_key


class Server:
    """Server implementation for hybrid authenticated handshake protocol.
    
    Encapsulates all server-side operations:
    0. Initialize with long-term signing keys (done once, reused across sessions)
    1. Generate ephemeral keys and sign handshake transcript (PHASE 2)
    2. Compute shared secrets and derive session key (PHASE 4)
    
    Attributes:
        sk_sign (bytes): Server's long-term ML-DSA-44 private signing key
                        (secret; never transmitted)
        session_key (bytes): Derived 32-byte hybrid session key (set after successful handshake)
    """
    
    def __init__(self, signing_private_key):
        """Initialize server with long-term signing key.
        
        Args:
            signing_private_key (bytes): Server's long-term ML-DSA-44 private key.
                                        This must be kept secret and used to sign all
                                        handshake transcripts.
        
        Raises:
            ValueError: If key is None or empty
        """
        if not signing_private_key:
            raise ValueError("Signing private key cannot be None or empty")
        
        self.sk_sign = signing_private_key
        self.session_key = None
        
        # Ephemeral keys (set in phase2)
        self._sk_dh = None
        self._pk_dh = None
        self._pk_kyber = None
        self._sk_kyber = None
    
    def phase2_generate_ephemeral_and_sign(self, client_pk_dh, client_pk_kyber):
        """PHASE 2: Generate ephemeral keys and sign handshake transcript.
        
        Server generates fresh ephemeral keys for this session and creates
        a signature over all four ephemeral public keys exchanged so far.
        This signature proves the server's identity and binds all keys together.
        
        Args:
            client_pk_dh (bytes): Client's ephemeral X25519 public key
                                 (received in PHASE 1)
            client_pk_kyber (bytes): Client's ephemeral ML-KEM-512 public key
                                    (received in PHASE 1)
        
        Returns:
            tuple: (pk_dh: bytes, pk_kyber: bytes, signature: bytes)
                   Server's ephemeral X25519 public key (32 bytes)
                   Server's ephemeral ML-KEM-512 public key (1184 bytes)
                   ML-DSA-44 signature over handshake transcript (2420 bytes)
        
        Security Note:
            The signature is computed over the canonical handshake transcript:
            transcript = LP(client_pk_dh) || LP(client_pk_kyber) || 
                        LP(server_pk_dh) || LP(server_pk_kyber)
            where LP(x) = len(x) as 4-byte big-endian || x
            
            This length-prefixing prevents ambiguity attacks on transcript boundaries.
        """
        
        # Generate ephemeral X25519 key pair
        self._sk_dh, self._pk_dh = dh_keygen()
        
        # Generate ephemeral Kyber/ML-KEM key pair
        self._pk_kyber, self._sk_kyber = kyber_keygen()
        
        # Sign the handshake transcript
        signature = server_sign_handshake(
            self.sk_sign,
            client_pk_dh, client_pk_kyber,
            self._pk_dh, self._pk_kyber
        )
        
        return self._pk_dh, self._pk_kyber, signature
    
    def phase4_derive_session_key(self, client_pk_dh, kyber_ciphertext):
        """PHASE 4: Compute shared secrets and derive hybrid session key.
        
        Server receives the client's ephemeral DH public key and Kyber ciphertext,
        then computes:
        1. DH shared secret using client's ephemeral public and server's ephemeral private
        2. Kyber shared secret by decapsulating the ciphertext
        3. Hybrid session key by combining both secrets through HKDF
        
        Args:
            client_pk_dh (bytes): Client's ephemeral X25519 public key
                                 (used as DH peer in scalar multiplication)
            kyber_ciphertext (bytes): Kyber ciphertext from client
                                     (contains encapsulated ephemeral shared secret)
        
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
        
        # Kyber shared secret: decapsulate ciphertext using server's ephemeral private
        ss_kyber = kyber_decapsulate(kyber_ciphertext, self._sk_kyber)
        
        # Derive hybrid session key by combining both secrets
        self.session_key = hybrid_session_key(ss_dh, ss_kyber)
        
        return self.session_key
    
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
