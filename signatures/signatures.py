"""
Digital Signature Module using Dilithium (ML-DSA)

This module provides post-quantum digital signatures for authenticating
ephemeral public keys during the handshake phase. Signatures ensure that
the exchanged public keys originate from a trusted party, preventing
man-in-the-middle attacks.

Cryptographic Purpose:
- Authentication: Signatures bind long-term identity keys to ephemeral handshake keys
- Non-repudiation: Only the holder of the private signing key can produce valid signatures
- Post-quantum security: Dilithium (ML-DSA) is resistant to quantum computer attacks

Usage Context:
- Signature key pairs are long-term identity keys (generated once, reused across sessions)
- During handshake: server signs the transcript of exchanged ephemeral public keys
- Client verifies signature before deriving shared secrets
- After handshake completes: signatures are no longer used; HMAC protects messages
"""

from dilithium_py.ml_dsa import ML_DSA_44

# ============================================================================
# NEW CODE: Post-Quantum Digital Signature Interface
# ============================================================================

def generate_keypair():
    """
    Generate a long-term Dilithium (ML-DSA) signing key pair.
    
    Cryptographic Purpose:
        These keys represent a party's long-term identity and are used to
        authenticate ephemeral keys during handshake. The public key must
        be distributed to peers through a trusted channel (e.g., certificates).
    
    Returns:
        tuple: (public_key: bytes, private_key: bytes)
            - public_key: Used by peers to verify signatures (can be shared publicly)
            - private_key: Used to create signatures (must remain secret)
    
    Security Note:
        ML-DSA-44 (Dilithium2) provides NIST Level 2 security, comparable to
        AES-128 against both classical and quantum adversaries.
    """
    public_key, private_key = ML_DSA_44.keygen()
    return public_key, private_key


def sign(private_key, message):
    """
    Sign a message using Dilithium (ML-DSA) private key.
    
    Cryptographic Purpose:
        In the handshake context, the 'message' is typically a transcript
        (concatenation) of all ephemeral public keys exchanged so far.
        The signature proves that the signer endorses these specific keys.
    
    Args:
        private_key (bytes): The signer's long-term private key
        message (bytes): The data to sign (e.g., handshake transcript)
    
    Returns:
        bytes: The digital signature
    
    Security Note:
        Dilithium signatures are deterministic for the same (key, message) pair,
        which eliminates risks from weak random number generators.
    """
    signature = ML_DSA_44.sign(private_key, message)
    return signature


def verify(public_key, message, signature):
    """
    Verify a Dilithium (ML-DSA) signature.
    
    Cryptographic Purpose:
        Before deriving shared secrets, the client MUST verify that the server's
        ephemeral public keys are properly signed. This prevents an attacker
        from substituting their own keys in the handshake.
    
    Args:
        public_key (bytes): The signer's long-term public key
        message (bytes): The original signed data (handshake transcript)
        signature (bytes): The signature to verify
    
    Returns:
        bool: True if signature is valid, False otherwise
    
    Security Note:
        If verification fails, the handshake MUST be aborted immediately.
        Proceeding with an unverified handshake exposes the session to MITM attacks.
    """
    try:
        # ML-DSA verify returns True on success, raises exception on failure
        return ML_DSA_44.verify(public_key, message, signature)
    except Exception:
        # Any verification failure returns False
        return False


# ============================================================================
# Helper Function for Handshake Transcript Construction
# ============================================================================

def build_handshake_transcript(client_dh_pub, client_kyber_pub, server_dh_pub, server_kyber_pub):
    """
    Construct the handshake transcript for signing/verification.
    
    Cryptographic Purpose:
        The transcript is a canonical byte representation of all ephemeral
        public keys exchanged during the handshake. By signing this transcript,
        the server cryptographically binds all keys together, ensuring that:
        1. The keys were chosen by the legitimate server
        2. The keys have not been modified in transit
        3. The keys belong to this specific handshake session
    
    Args:
        client_dh_pub (bytes): Client's ephemeral DH public key
        client_kyber_pub (bytes): Client's ephemeral Kyber public key  
        server_dh_pub (bytes): Server's ephemeral DH public key
        server_kyber_pub (bytes): Server's ephemeral Kyber public key
    
    Returns:
        bytes: Concatenated transcript ready for signing
    
    Note:
        The order of concatenation must be consistent between signer and verifier.
        Using length-prefixing prevents ambiguity in parsing.
    """
    # Length-prefix each component to ensure unambiguous parsing
    # This prevents attacks where key boundaries are manipulated
    def length_prefix(data):
        """Prefix data with its 4-byte length (big-endian)"""
        return len(data).to_bytes(4, 'big') + data
    
    transcript = (
        length_prefix(client_dh_pub) +
        length_prefix(client_kyber_pub) +
        length_prefix(server_dh_pub) +
        length_prefix(server_kyber_pub)
    )
    
    return transcript
