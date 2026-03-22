# X25519 DH KEM module
from .kem import (
    # New API
    dh_keygen,
    dh_shared_secret,
    dh_public_from_private,
    # Legacy functions (deprecated - backward compat)
    kem_keygen,
    kem_encapsulate,
    kem_decapsulate
)
