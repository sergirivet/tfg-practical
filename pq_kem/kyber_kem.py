import oqs

def kyber_keygen():
    """Genera un par de claves Kyber512 (ML-KEM)."""
    kem = oqs.KeyEncapsulation("Kyber512")
    public_key = kem.generate_keypair()
    private_key = kem.export_secret_key()
    return public_key, private_key

def kyber_encapsulate(public_key):
    """Encapsula un secreto usando la clave pública Kyber."""
    kem = oqs.KeyEncapsulation("Kyber512")
    ciphertext, shared_secret = kem.encap_secret(public_key)
    return ciphertext, shared_secret

def kyber_decapsulate(ciphertext, private_key):
    """Decapsula el secreto usando la clave privada Kyber."""
    kem = oqs.KeyEncapsulation("Kyber512", private_key)
    shared_secret = kem.decap_secret(ciphertext)
    return shared_secret
