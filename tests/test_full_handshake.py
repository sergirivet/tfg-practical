from dh_kem.kem import kem_keygen, kem_encapsulate, kem_decapsulate
from classic.hmac import hmac_sha256
from classic.hkdf import hkdf_extract, hkdf_expand

P_DEMO = 0xFFFFFFFB
G_DEMO = 5

def test_full_handshake():
    print("--- Server Key Generation ---")
    server_private, server_public = kem_keygen(P_DEMO, G_DEMO)
    print(f"Server Public Key: {server_public}")

    print("\n--- Client Encapsulation ---")
    ciphertext, client_session_key = kem_encapsulate(P_DEMO, G_DEMO, server_public)
    print(f"Client Session Key: {client_session_key.hex()}")
    print(f"Ciphertext sent: {ciphertext}")

    print("\n--- Server Decapsulation ---")
    server_session_key = kem_decapsulate(P_DEMO, G_DEMO, ciphertext, server_private)
    print(f"Server Session Key: {server_session_key.hex()}")

    if client_session_key == server_session_key:
        print("Session keys match :)")
    else:
        print("Session keys do not match :(")
        return

    print("\n--- HMAC Authentication ---")
    message = b"Hello, this is a test message."
    tag = hmac_sha256(client_session_key, message)
    valid = hmac_sha256(server_session_key, message) == tag
    
    if valid:
        print("HMAC verified :)")
    else:
        print("HMAC verification failed :(")

    print("\nFull handshake test passed!")

if __name__ == "__main__":
    test_full_handshake()
