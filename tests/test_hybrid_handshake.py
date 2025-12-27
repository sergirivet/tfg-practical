from dh_kem.kem import kem_keygen, kem_encapsulate, kem_decapsulate
from pq_kem.kyber_kem import kyber_keygen, kyber_encapsulate, kyber_decapsulate
from hybrid.hybrid_handshake import hybrid_session_key
from classic.hmac import hmac_sha256

P_DEMO = 0xFFFFFFFB
G_DEMO = 5

def test_hybrid_handshake():
    # DH classical key generation
    dh_priv, dh_pub = kem_keygen(P_DEMO, G_DEMO)

    # Kyber key generation
    kyber_pub, kyber_priv = kyber_keygen()

    # Client side
    dh_ct, dh_client_key = kem_encapsulate(P_DEMO, G_DEMO, dh_pub)
    kyber_ct, kyber_client_secret = kyber_encapsulate(kyber_pub)

    # Server side
    dh_server_key = kem_decapsulate(P_DEMO, G_DEMO, dh_ct, dh_priv)
    kyber_server_secret = kyber_decapsulate(kyber_ct, kyber_priv)

    # Combine secrets
    final_client_key = hybrid_session_key(dh_client_key, kyber_client_secret)
    final_server_key = hybrid_session_key(dh_server_key, kyber_server_secret)

    print("Final Client Key:", final_client_key.hex())
    print("Final Server Key:", final_server_key.hex())

    if final_client_key == final_server_key:
        print("Hybrid session keys match :)")
    else:
        print("Hybrid session keys do not match :(")
        return

    message = b"Hello, this is a hybrid test."
    tag = hmac_sha256(final_client_key, message)
    valid = hmac_sha256(final_server_key, message) == tag

    if valid:
        print("Hybrid HMAC verified :)")
    else:
        print("Hybrid HMAC verification failed :(")

if __name__ == "__main__":
    test_hybrid_handshake()
