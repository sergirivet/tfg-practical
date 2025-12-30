from kyber_py.ml_kem import ML_KEM_512

def kyber_keygen():
    """Genera un par de claves Kyber512 (ML-KEM)."""
    public_key, private_key = ML_KEM_512.keygen()
    return public_key, private_key

def kyber_encapsulate(public_key):
    """Encapsula un secreto usando la clave pública Kyber."""
    ciphertext, shared_secret = ML_KEM_512.encaps(public_key)
    return ciphertext, shared_secret

def kyber_decapsulate(ciphertext, private_key):
    """Decapsula el secreto usando la clave privada Kyber."""
    shared_secret = ML_KEM_512.decaps(private_key, ciphertext)
    return shared_secret
