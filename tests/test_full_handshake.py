"""
Test: Basic Full Handshake (Static-Ephemeral DH)

This test demonstrates a simple handshake without authentication:
1. Server generates a static key pair
2. Client generates ephemeral key pair
3. Both parties derive same shared secret via DH
4. HMAC verifies message integrity post-handshake

Note: This demonstrates the classical DH component. For authenticated
handshake with post-quantum signatures, see test_authenticated_handshake.py
"""

from dh_kem.kem import kem_keygen, kem_encapsulate, kem_decapsulate
from classic.hmac import hmac_sha256

# Legacy test parameters (kept for backward compatibility)
P_DEMO = 0xFFFFFFFB
G_DEMO = 5

def test_full_handshake():
    print("=" * 60)
    print("TEST: Full Handshake (Static-Ephemeral DH)")
    print("=" * 60)
    
    print("\n--- Server Key Generation (Static) ---")
    server_private, server_public = kem_keygen(P_DEMO, G_DEMO)
    print(f"Server Public Key: {server_public.hex()[:32]}... (truncated)")

    print("\n--- Client Encapsulation (Ephemeral) ---")
    ciphertext, client_session_key = kem_encapsulate(P_DEMO, G_DEMO, server_public)
    print(f"Client Session Key: {client_session_key.hex()}")
    print(f"Ciphertext (client ephemeral pk): {ciphertext.hex()[:32]}... (truncated)")

    print("\n--- Server Decapsulation ---")
    server_session_key = kem_decapsulate(P_DEMO, G_DEMO, ciphertext, server_private)
    print(f"Server Session Key: {server_session_key.hex()}")

    if client_session_key == server_session_key:
        print("✓ Session keys match")
    else:
        print("✗ Session keys do not match")
        return False

    print("\n--- HMAC Authentication (Post-Handshake) ---")
    message = b"Hello, this is a test message."
    tag = hmac_sha256(client_session_key, message)
    valid = hmac_sha256(server_session_key, message) == tag
    
    if valid:
        print("✓ HMAC verified")
    else:
        print("✗ HMAC verification failed")
        return False

    print("\n" + "=" * 60)
    print("FULL HANDSHAKE TEST PASSED!")
    print("=" * 60)
    return True

if __name__ == "__main__":
    test_full_handshake()
