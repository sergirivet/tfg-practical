from classic.hmac import hmac_sha256

HASH_OUTPUT_LEN = 32

def hkdf_extract(salt: bytes | None, ikm: bytes) -> bytes:
    if salt is None or len(salt) == 0:
        salt = bytes([0] * HASH_OUTPUT_LEN)
    return hmac_sha256(salt, ikm)

def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    hash_len = HASH_OUTPUT_LEN
    n_blocks = -(-length // hash_len)
    output_key_material = b""
    previous_block = b""
    for counter in range(1, n_blocks + 1):
        previous_block = hmac_sha256(prk, previous_block + info + bytes([counter]))
        output_key_material += previous_block
    return output_key_material[:length]
