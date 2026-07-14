from kyber_py.ml_kem import ML_KEM_512

from primitives.base import KEM

def kyber_keygen():
    """Generate a fresh Kyber512 (ML-KEM) key pair."""
    public_key, private_key = ML_KEM_512.keygen()
    return public_key, private_key

def kyber_encapsulate(public_key):
    """Encapsulate a shared secret using Kyber public key."""
    shared_secret, ciphertext = ML_KEM_512.encaps(public_key)
    return ciphertext, shared_secret

def kyber_decapsulate(ciphertext, private_key):
    """Decapsulate a shared secret using Kyber private key."""
    shared_secret = ML_KEM_512.decaps(private_key, ciphertext)
    return shared_secret


class MLKEM512Engine(KEM):
    """Concrete KEM adapter for ML-KEM-512."""

    def keygen(self):
        public_key, private_key = kyber_keygen()
        return private_key, public_key

    def encapsulate(self, public_key: bytes):
        ciphertext, shared_secret = kyber_encapsulate(public_key)
        return shared_secret, ciphertext

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        return kyber_decapsulate(ciphertext, secret_key)
