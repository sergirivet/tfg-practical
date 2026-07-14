"""Key encapsulation primitives and engines."""

from .classical import X25519Engine, dh_keygen, dh_public_from_private, dh_shared_secret
from .hybrid import HybridKEMEngine
from .quantum import MLKEM512Engine, kyber_decapsulate, kyber_encapsulate, kyber_keygen

