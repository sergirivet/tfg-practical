"""
Classical Digital Signature Module using ECDSA (P-256)

This module provides classical (non-post-quantum) digital signatures using
ECDSA with the NIST P-256 (secp256r1) curve as the classical counterpart
to the post-quantum Dilithium signatures.

Cryptographic Purpose:
- Authentication: ECDSA signatures authenticate ephemeral public keys during handshake
- Non-repudiation: Only the holder of the private signing key can produce valid signatures
- Classical security: Proven cryptographic foundation (complement to post-quantum Dilithium)

Hybrid Authentication Layer:
- This module provides the "classical half" of hybrid authentication
- Dilithium handles post-quantum security
- Together they provide defense-in-depth: if either algorithm is compromised,
  the other continues to provide security
- Both signatures are computed on the same message (handshake transcript)

Security Considerations:
- ECDSA with P-256 provides approximately 128 bits of classical security
- Resistant to classical cryptanalysis but vulnerable to quantum computers
- Deterministic ECDSA (RFC 6979) is used to prevent signature randomness attacks
- Signature verification must succeed for both classical and post-quantum schemes
  in hybrid mode before proceeding with key derivation
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

# ============================================================================
# ECDSA with P-256 (NIST secp256r1) Digital Signature Interface
# ============================================================================

def generate_keypair():
    """
    Generate a long-term ECDSA (P-256) signing key pair.
    
    Cryptographic Purpose:
        These keys represent a party's long-term identity for classical authentication.
        They complement Dilithium keys for hybrid authentication. Public key should
        be distributed through a trusted channel (e.g., certificates).
    
    Returns:
        tuple: (public_key: bytes, private_key: bytes)
            - public_key: Used by peers to verify signatures (can be shared publicly)
            - private_key: Used to create signatures (must remain secret)
    
    Security Note:
        P-256 (secp256r1 / NIST curve) provides 128 bits of classical security.
        The private key is serialized in PKCS8 format for compatibility.
        The public key is serialized in SubjectPublicKeyInfo format.
    """
    # Generate a new private key for P-256
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    
    # Extract public key
    public_key = private_key.public_key()
    
    # Serialize both keys to bytes
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return public_key_bytes, private_key_bytes


def sign(private_key, message):
    """
    Sign a message using ECDSA (P-256) private key.
    
    Cryptographic Purpose:
        In the hybrid handshake context, the 'message' is typically a transcript
        (concatenation) of all ephemeral public keys exchanged so far.
        The classical signature proves classical authentication alongside the PQ signature.
    
    Args:
        private_key (bytes): The signer's long-term ECDSA private key (PEM format)
        message (bytes): The data to sign (e.g., handshake transcript)
    
    Returns:
        bytes: The ECDSA signature (DER format)
    
    Implementation Notes:
        - Uses RFC 6979 deterministic ECDSA to avoid randomness issues
        - Signature is in DER format for standardization
        - SHA-256 is used as the hash algorithm
    """
    # Load private key from bytes
    private_key_obj = serialization.load_pem_private_key(
        private_key,
        password=None,
        backend=default_backend()
    )
    
    # Sign the message using ECDSA with SHA-256
    # RFC 6979 deterministic ECDSA is used automatically by cryptography lib
    signature = private_key_obj.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )
    
    return signature


def verify(public_key, message, signature):
    """
    Verify an ECDSA (P-256) signature.
    
    Cryptographic Purpose:
        Before deriving shared secrets in hybrid mode, the client MUST verify
        both the classical ECDSA signature AND the post-quantum Dilithium signature.
        This ensures both classical and PQ-safe authentication channels are intact.
    
    Args:
        public_key (bytes): The signer's long-term ECDSA public key (PEM format)
        message (bytes): The original signed data (handshake transcript)
        signature (bytes): The signature to verify (DER format)
    
    Returns:
        bool: True if signature is valid, False otherwise
    
    Security Note:
        If verification fails (for either ECDSA or Dilithium), the handshake
        MUST be aborted immediately. Proceeding with failed verification exposes
        the session to classical or quantum MITM attacks respectively.
    """
    try:
        # Load public key from bytes
        public_key_obj = serialization.load_pem_public_key(
            public_key,
            backend=default_backend()
        )
        
        # Verify the signature
        public_key_obj.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )
        
        return True
    except Exception:
        # Any verification failure (invalid signature, corrupted data, etc.)
        return False
