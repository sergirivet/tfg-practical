import secrets
from classic.hkdf import hkdf_extract, hkdf_expand

def int_to_bytes(x):
    length = (x.bit_length() + 7) // 8
    return x.to_bytes(length, 'big')

# --- Curve25519 Parameters ---
# Prime: p = 2^255 - 19
P25519 = (1 << 255) - 19
# Coefficient A = 486662 for Montgomery curve: y² = x³ + Ax² + x
A25519 = 486662
# Base point x-coordinate (generator)
G25519 = 9

# --- Finite Field Arithmetic (mod p) ---
def mod_inv(a, p):
    """Modular inverse using Fermat's little theorem: a^(-1) = a^(p-2) mod p"""
    return pow(a, p - 2, p)

# --- Montgomery Ladder for X25519 ---
def x25519_scalar_mult(k, u):
    """
    Scalar multiplication on Curve25519 using Montgomery ladder.
    k: scalar (integer)
    u: x-coordinate of point (integer)
    Returns: x-coordinate of k*P
    """
    p = P25519
    a24 = (A25519 - 2) // 4  # a24 = 121665 for Curve25519
    
    # Initialize: (x_1, x_2, z_2, x_3, z_3)
    x_1 = u
    x_2 = 1
    z_2 = 0
    x_3 = u
    z_3 = 1
    swap = 0
    
    # Process bits from 254 down to 0 (255 bits, but bit 255 is always 0 after clamping)
    for t in range(254, -1, -1):
        k_t = (k >> t) & 1
        swap ^= k_t
        
        # Conditional swap
        if swap:
            x_2, x_3 = x_3, x_2
            z_2, z_3 = z_3, z_2
        swap = k_t
        
        # Montgomery ladder step
        A = (x_2 + z_2) % p
        AA = (A * A) % p
        B = (x_2 - z_2) % p
        BB = (B * B) % p
        E = (AA - BB) % p
        C = (x_3 + z_3) % p
        D = (x_3 - z_3) % p
        DA = (D * A) % p
        CB = (C * B) % p
        x_3 = pow(DA + CB, 2, p)
        z_3 = (x_1 * pow(DA - CB, 2, p)) % p
        x_2 = (AA * BB) % p
        z_2 = (E * (AA + a24 * E)) % p
    
    # Final conditional swap
    if swap:
        x_2, x_3 = x_3, x_2
        z_2, z_3 = z_3, z_2
    
    # Compute result: x_2 * z_2^(-1) mod p
    return (x_2 * mod_inv(z_2, p)) % p

def clamp_scalar(k_bytes):
    """Apply X25519 clamping to scalar bytes (RFC 7748)"""
    k_list = list(k_bytes)
    k_list[0] &= 248      # Clear bottom 3 bits
    k_list[31] &= 127     # Clear top bit
    k_list[31] |= 64      # Set second-to-top bit
    return bytes(k_list)

def bytes_to_int_le(b):
    """Convert bytes to integer (little-endian)"""
    return int.from_bytes(b, 'little')

def int_to_bytes_le(x, length=32):
    """Convert integer to bytes (little-endian)"""
    return x.to_bytes(length, 'little')

# --- Primitivas Diffie-Hellman (X25519 manual) ---
# ============================================================================
# X25519 Diffie-Hellman (RFC 7748)
# ============================================================================

def dh_keygen():
    """Generate a fresh X25519 ephemeral key pair.
    
    Returns:
        tuple: (private_key: bytes, public_key: bytes)
            Both 32-byte values for X25519
    """
    raw = secrets.token_bytes(32)
    private = clamp_scalar(raw)
    public = dh_public_from_private(private)
    return private, public

def dh_public_from_private(private_key):
    """Compute X25519 public key from private key.
    
    Args:
        private_key: 32-byte private key (after clamping)
    
    Returns:
        bytes: 32-byte X25519 public key (x-coordinate)
    """
    k = bytes_to_int_le(private_key)
    result = x25519_scalar_mult(k, G25519)
    return int_to_bytes_le(result)

def dh_shared_secret(private_key, public_key):
    """Compute X25519 shared secret.
    
    Performs: private_key * public_key (scalar multiplication on curve)
    
    Args:
        private_key: 32-byte private key
        public_key: 32-byte public key (x-coordinate from other party)
    
    Returns:
        bytes: 32-byte shared secret (x-coordinate)
    """
    if isinstance(public_key, bytes):
        u = bytes_to_int_le(public_key)
    else:
        u = public_key
    k = bytes_to_int_le(private_key)
    result = x25519_scalar_mult(k, u)
    return int_to_bytes_le(result)

# ============================================================================
# Legacy KEM functions (kept for backward compatibility with old tests)
# Note: These are deprecated in favor of direct dh_keygen() + dh_shared_secret()
# ============================================================================

def kem_keygen(p, g):
    """DEPRECATED: Use dh_keygen() instead.
    Generate X25519 key pair (ignores p, g parameters).
    """
    return dh_keygen()

def kem_encapsulate(p, g, server_static_public, info=b"handshake context"):
    """DEPRECATED: Use dh_keygen() + dh_shared_secret() instead.
    Client-side: generate ephemeral key and compute shared secret.
    """
    client_ephemeral_private, client_ephemeral_public = dh_keygen()
    raw_secret = dh_shared_secret(client_ephemeral_private, server_static_public)
    prk = hkdf_extract(None, raw_secret)
    session_key = hkdf_expand(prk, info, 32)
    ciphertext = client_ephemeral_public
    return ciphertext, session_key

def kem_decapsulate(p, g, ciphertext, server_static_private, info=b"handshake context"):
    """DEPRECATED: Use dh_shared_secret() instead.
    Server-side: decapsulate and compute shared secret.
    """
    raw_secret = dh_shared_secret(server_static_private, ciphertext)
    prk = hkdf_extract(None, raw_secret)
    session_key = hkdf_expand(prk, info, 32)
    return session_key
