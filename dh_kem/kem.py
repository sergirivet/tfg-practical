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
def dh_generate_private_key(p):
    """Generate a random 32-byte private key with clamping"""
    raw = secrets.token_bytes(32)
    return clamp_scalar(raw)

def dh_generate_public_key(g, private_key, p):
    """Compute public key: private_key * G (base point)"""
    k = bytes_to_int_le(private_key)
    result = x25519_scalar_mult(k, G25519)
    return int_to_bytes_le(result)

def dh_compute_shared_secret(other_public, private_key, p):
    """Compute shared secret: private_key * other_public"""
    if isinstance(other_public, bytes):
        u = bytes_to_int_le(other_public)
    else:
        u = other_public
    k = bytes_to_int_le(private_key)
    result = x25519_scalar_mult(k, u)
    return int_to_bytes_le(result)

def dh_generate_keypair(p, g):
    private = dh_generate_private_key(p)
    public = dh_generate_public_key(g, private, p)
    return private, public

# --- DH-based KEM ---
def kem_keygen(p, g):
    """Servidor: genera clave estática"""
    return dh_generate_keypair(p, g)

def kem_encapsulate(p, g, server_static_public, info=b"handshake context"):
    """Cliente: encapsula y genera clave simétrica"""
    client_ephimeral_private, client_ephimeral_public = dh_generate_keypair(p, g)
    raw_secret = dh_compute_shared_secret(server_static_public, client_ephimeral_private, p)
    prk = hkdf_extract(None, raw_secret)
    session_key = hkdf_expand(prk, info, 32)
    ciphertext = client_ephimeral_public
    return ciphertext, session_key

def kem_decapsulate(p, g, ciphertext, server_static_private, info=b"handshake context"):
    """Servidor: decapsula y obtiene la misma clave simétrica"""
    raw_secret = dh_compute_shared_secret(ciphertext, server_static_private, p)
    prk = hkdf_extract(None, raw_secret)
    session_key = hkdf_expand(prk, info, 32)
    return session_key
