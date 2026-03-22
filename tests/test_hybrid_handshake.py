"""
Test: Hybrid Handshake (Non-Authenticated)

This test demonstrates the hybrid combination of DH and Kyber KEM
without authentication (no digital signatures).

For authenticated version with signatures, see test_authenticated_handshake.py
and test_protocol_3_4.py
"""

from dh_kem.kem import kem_keygen, kem_encapsulate, kem_decapsulate
from pq_kem.kyber_kem import kyber_keygen, kyber_encapsulate, kyber_decapsulate
from hybrid.hybrid_handshake import hybrid_session_key
from classic.hmac import hmac_sha256

P_DEMO = 0xFFFFFFFB
G_DEMO = 5

def test_hybrid_handshake():
    """Test basic hybrid DH+Kyber combination without authentication."""
    
    print("=" * 60)
    print("TEST: Hybrid Handshake (DH + Kyber)")
    print("=" * 60)
    
    # DH classical key generation (static)
    print("\n--- DH Key Generation (Static) ---")
    dh_priv, dh_pub = kem_keygen(P_DEMO, G_DEMO)
    print(f"DH Public: {dh_pub.hex()}")

    # Kyber key generation
    print("\n--- Kyber Key Generation ---")
    kyber_pub, kyber_priv = kyber_keygen()
    print(f"Kyber Public: {kyber_pub[:32].hex()}... (truncated)")

    # Client side
    print("\n--- Client Side ---")
    dh_ct, dh_client_key = kem_encapsulate(P_DEMO, G_DEMO, dh_pub)
    kyber_ct, kyber_client_secret = kyber_encapsulate(kyber_pub)
    print(f"Client DH key: {dh_client_key.hex()}")
    print(f"Client Kyber secret: {kyber_client_secret.hex()}")

    # Server side
    print("\n--- Server Side ---")
    dh_server_key = kem_decapsulate(P_DEMO, G_DEMO, dh_ct, dh_priv)
    kyber_server_secret = kyber_decapsulate(kyber_ct, kyber_priv)
    print(f"Server DH key: {dh_server_key.hex()}")
    print(f"Server Kyber secret: {kyber_server_secret.hex()}")

    # Combine secrets using hybrid_session_key
    print("\n--- Hybrid Combination (DH || Kyber) ---")
    final_client_key = hybrid_session_key(dh_client_key, kyber_client_secret)
    final_server_key = hybrid_session_key(dh_server_key, kyber_server_secret)

    print(f"Final Client Key: {final_client_key.hex()}")
    print(f"Final Server Key: {final_server_key.hex()}")

    if final_client_key == final_server_key:
        print("✓ Hybrid session keys match")
    else:
        print("✗ Hybrid session keys do not match")
        return False

    # Post-handshake HMAC authentication
    print("\n--- HMAC Authentication (Post-Handshake) ---")
    message = b"Hello, this is a hybrid test."
    tag = hmac_sha256(final_client_key, message)
    valid = hmac_sha256(final_server_key, message) == tag

    if valid:
        print("✓ Hybrid HMAC verified")
    else:
        print("✗ Hybrid HMAC verification failed")
        return False
    
    print("\n" + "=" * 60)
    print("HYBRID HANDSHAKE TEST PASSED!")
    print("=" * 60)
    return True


if __name__ == "__main__":
    success = test_hybrid_handshake()
    if not success:
        exit(1)
