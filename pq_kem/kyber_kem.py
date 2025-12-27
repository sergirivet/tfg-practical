from pqcrypto.kem.kyber512 import generate_keypair, encrypt, decrypt

def kyber_keygen():
    return generate_keypair()

def kyber_encapsulate(pub_key):
    return encrypt(pub_key)

def kyber_decapsulate(ciphertext, priv_key):
    return decrypt(ciphertext, priv_key)
