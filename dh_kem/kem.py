import secrets
from classic.hkdf import hkdf_extract, hkdf_expand

def int_to_bytes(x):
    length = (x.bit_length() + 7) // 8
    return x.to_bytes(length, 'big')

# --- Primitivas Diffie-Hellman ---
def dh_generate_private_key(p):
    return secrets.randbelow(p - 2) + 1

def dh_generate_public_key(g, private_key, p):
    return pow(g, private_key, p)

def dh_compute_shared_secret(other_public, private_key, p):
    return pow(other_public, private_key, p)

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
    secret_bytes = int_to_bytes(raw_secret)
    prk = hkdf_extract(None, secret_bytes)
    session_key = hkdf_expand(prk, info, 32)
    ciphertext = client_ephimeral_public
    return ciphertext, session_key

def kem_decapsulate(p, g, ciphertext, server_static_private, info=b"handshake context"):
    """Servidor: decapsula y obtiene la misma clave simétrica"""
    raw_secret = dh_compute_shared_secret(ciphertext, server_static_private, p)
    secret_bytes = int_to_bytes(raw_secret)
    prk = hkdf_extract(None, secret_bytes)
    session_key = hkdf_expand(prk, info, 32)
    return session_key
