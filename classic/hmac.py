import hashlib

def sha256(data):
    """Hash SHA-256."""
    return hashlib.sha256(data).digest()

def hmac_sha256(key, message):
    """
    Implementación HMAC-SHA256 manual.
    Garantiza autenticidad e integridad de un mensaje.
    """
    block_size = 64  # SHA-256 usa bloques de 64 bytes

    # Normalizar clave
    if len(key) > block_size:
        key = sha256(key)
    if len(key) < block_size:
        key = key + b'\x00' * (block_size - len(key))

    # Crear ipad y opad
    ipad = bytes([0x36] * block_size)
    opad = bytes([0x5C] * block_size)

    # Inner hash
    inner_input = bytes([k ^ i for k, i in zip(key, ipad)]) + message
    inner_hash = sha256(inner_input)

    # Outer hash
    outer_input = bytes([k ^ o for k, o in zip(key, opad)]) + inner_hash
    final_hash = sha256(outer_input)

    return final_hash
