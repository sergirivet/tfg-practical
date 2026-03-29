import hashlib

def sha256(data):
    """Hash SHA-256."""
    return hashlib.sha256(data).digest()

def hmac_sha256(key, message):
    """
    Compute HMAC-SHA256 to ensure message authenticity and integrity.
    """
    block_size = 64  # SHA-256 block size in bytes

    # Normalize key to block size (hash if too long, pad with zeros if too short)
    if len(key) > block_size:
        key = sha256(key)
    if len(key) < block_size:
        key = key + b'\x00' * (block_size - len(key))

    # Create inner and outer padding
    ipad = bytes([0x36] * block_size)
    opad = bytes([0x5C] * block_size)

    # Compute inner hash
    inner_input = bytes([k ^ i for k, i in zip(key, ipad)]) + message
    inner_hash = sha256(inner_input)

    # Compute outer hash
    outer_input = bytes([k ^ o for k, o in zip(key, opad)]) + inner_hash
    final_hash = sha256(outer_input)

    return final_hash
