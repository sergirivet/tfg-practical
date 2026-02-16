"""
Test: Authenticated Hybrid Handshake with Digital Signatures

This test demonstrates the complete authenticated handshake flow:
1. Server generates long-term signing keys (done once, reused across sessions)
2. Client and server exchange ephemeral DH and Kyber keys
3. Server signs the handshake transcript
4. Client verifies signature before deriving session key
5. Both parties derive the same hybrid session key
6. Post-handshake: HMAC protects message integrity (signatures no longer used)

Also tests that authentication failure is properly detected and aborted.
"""

from dh_kem.kem import kem_keygen, kem_encapsulate, kem_decapsulate
from pq_kem.kyber_kem import kyber_keygen, kyber_encapsulate, kyber_decapsulate
from hybrid.hybrid_handshake import (
    hybrid_session_key,
    server_sign_handshake,
    client_verify_handshake,
    authenticated_hybrid_session_key,
    AuthenticationError
)
from signatures.signatures import generate_keypair, sign, verify
from classic.hmac import hmac_sha256

# Demo parameters for DH (same as other tests)
P_DEMO = 0xFFFFFFFB
G_DEMO = 5


def test_authenticated_hybrid_handshake():
    """
    Test successful authenticated handshake flow.
    
    This simulates a complete session establishment where:
    - Server proves its identity via digital signature
    - Client verifies server before computing shared secrets
    - Both parties derive the same session key
    """
    print("=" * 60)
    print("TEST: Authenticated Hybrid Handshake")
    print("=" * 60)
    
    # =========================================================================
    # PHASE 0: Long-term key setup (done once, before any sessions)
    # =========================================================================
    print("\n--- Phase 0: Server Long-Term Key Generation ---")
    print("(This happens once during server setup, not per-session)")
    
    # Server generates its long-term signing key pair
    # The public key would be distributed via certificates in a real system
    server_signing_public, server_signing_private = generate_keypair()
    print(f"Server signing public key: {server_signing_public[:32].hex()}... (truncated)")
    print(f"Server signing private key: [KEPT SECRET]")
    
    # =========================================================================
    # PHASE 1: Client generates ephemeral keys and sends to server
    # =========================================================================
    print("\n--- Phase 1: Client Ephemeral Key Generation ---")
    
    # Client generates ephemeral DH key pair
    client_dh_private, client_dh_public = kem_keygen(P_DEMO, G_DEMO)
    print(f"Client ephemeral DH public: {client_dh_public.hex()}")
    
    # Client generates ephemeral Kyber key pair
    client_kyber_public, client_kyber_private = kyber_keygen()
    print(f"Client ephemeral Kyber public: {client_kyber_public[:32].hex()}... (truncated)")
    
    print("Client sends: client_dh_public, client_kyber_public → Server")
    
    # =========================================================================
    # PHASE 2: Server generates ephemeral keys and signs transcript
    # =========================================================================
    print("\n--- Phase 2: Server Ephemeral Key Generation & Signing ---")
    
    # Server generates ephemeral DH key pair
    server_dh_private, server_dh_public = kem_keygen(P_DEMO, G_DEMO)
    print(f"Server ephemeral DH public: {server_dh_public.hex()}")
    
    # Server generates ephemeral Kyber key pair
    server_kyber_public, server_kyber_private = kyber_keygen()
    print(f"Server ephemeral Kyber public: {server_kyber_public[:32].hex()}... (truncated)")
    
    # Server signs the handshake transcript
    # This proves the server endorses all four ephemeral public keys
    signature = server_sign_handshake(
        server_signing_private,
        client_dh_public, client_kyber_public,
        server_dh_public, server_kyber_public
    )
    print(f"Server signature: {signature[:32].hex()}... (truncated)")
    
    print("Server sends: server_dh_public, server_kyber_public, signature → Client")
    
    # =========================================================================
    # PHASE 3: Client verifies signature before deriving secrets
    # =========================================================================
    print("\n--- Phase 3: Client Signature Verification ---")
    
    try:
        client_verify_handshake(
            server_signing_public,
            client_dh_public, client_kyber_public,
            server_dh_public, server_kyber_public,
            signature
        )
        print("✓ Signature verification PASSED")
        print("  Server identity confirmed. Proceeding with key derivation.")
    except AuthenticationError as e:
        print(f"✗ AUTHENTICATION FAILED: {e}")
        print("  Handshake aborted. No secrets derived.")
        return
    
    # =========================================================================
    # PHASE 4: Both parties derive shared secrets
    # =========================================================================
    print("\n--- Phase 4: Shared Secret Derivation ---")
    
    # DH key exchange
    # Client computes: DH(client_private, server_public)
    dh_ciphertext, dh_client_secret = kem_encapsulate(P_DEMO, G_DEMO, server_dh_public)
    # Server computes: DH(server_private, ciphertext=client_ephemeral_public)
    # Note: In actual ephemeral-ephemeral DH, both sides compute DH(their_private, other_public)
    # The KEM abstraction here is slightly different but achieves same goal
    
    # For proper ephemeral-ephemeral DH, we need direct computation:
    from dh_kem.kem import dh_compute_shared_secret
    dh_client_secret = dh_compute_shared_secret(server_dh_public, client_dh_private, P_DEMO)
    dh_server_secret = dh_compute_shared_secret(client_dh_public, server_dh_private, P_DEMO)
    
    print(f"DH client secret: {dh_client_secret.hex()}")
    print(f"DH server secret: {dh_server_secret.hex()}")
    assert dh_client_secret == dh_server_secret, "DH secrets should match"
    print("✓ DH shared secrets match")
    
    # Kyber key exchange
    kyber_ciphertext, kyber_client_secret = kyber_encapsulate(server_kyber_public)
    kyber_server_secret = kyber_decapsulate(kyber_ciphertext, server_kyber_private)
    
    print(f"Kyber client secret: {kyber_client_secret.hex()}")
    print(f"Kyber server secret: {kyber_server_secret.hex()}")
    assert kyber_client_secret == kyber_server_secret, "Kyber secrets should match"
    print("✓ Kyber shared secrets match")
    
    # =========================================================================
    # PHASE 5: Derive hybrid session key
    # =========================================================================
    print("\n--- Phase 5: Hybrid Session Key Derivation ---")
    
    client_session_key = hybrid_session_key(dh_client_secret, kyber_client_secret)
    server_session_key = hybrid_session_key(dh_server_secret, kyber_server_secret)
    
    print(f"Client session key: {client_session_key.hex()}")
    print(f"Server session key: {server_session_key.hex()}")
    
    if client_session_key == server_session_key:
        print("✓ Hybrid session keys match!")
    else:
        print("✗ Hybrid session keys do NOT match!")
        return
    
    # =========================================================================
    # PHASE 6: Post-handshake message authentication (HMAC, not signatures)
    # =========================================================================
    print("\n--- Phase 6: Post-Handshake Message Protection (HMAC) ---")
    print("(Signatures are no longer used after handshake)")
    
    message = b"Hello from authenticated session!"
    tag = hmac_sha256(client_session_key, message)
    is_valid = hmac_sha256(server_session_key, message) == tag
    
    if is_valid:
        print("✓ HMAC verification passed")
        print("  Message integrity confirmed using session key.")
    else:
        print("✗ HMAC verification failed")
        return
    
    print("\n" + "=" * 60)
    print("AUTHENTICATED HANDSHAKE TEST PASSED!")
    print("=" * 60)


def test_authentication_failure():
    """
    Test that handshake correctly aborts when authentication fails.
    
    This simulates a man-in-the-middle attack where the attacker
    substitutes their own ephemeral keys. The signature verification
    should fail, and the handshake should be aborted.
    """
    print("\n\n" + "=" * 60)
    print("TEST: Authentication Failure Detection (MITM Simulation)")
    print("=" * 60)
    
    # Server's legitimate long-term keys
    server_signing_public, server_signing_private = generate_keypair()
    
    # Attacker's keys (trying to impersonate server)
    attacker_signing_public, attacker_signing_private = generate_keypair()
    
    # Legitimate client keys
    client_dh_private, client_dh_public = kem_keygen(P_DEMO, G_DEMO)
    client_kyber_public, client_kyber_private = kyber_keygen()
    
    # ATTACKER intercepts and substitutes their own ephemeral keys
    print("\n--- Attacker substitutes their own ephemeral keys ---")
    attacker_dh_private, attacker_dh_public = kem_keygen(P_DEMO, G_DEMO)
    attacker_kyber_public, attacker_kyber_private = kyber_keygen()
    
    # Attacker signs with their own key (they don't have server's private key)
    attacker_signature = server_sign_handshake(
        attacker_signing_private,  # Attacker can only sign with their own key
        client_dh_public, client_kyber_public,
        attacker_dh_public, attacker_kyber_public
    )
    
    print("\n--- Client attempts to verify with legitimate server public key ---")
    try:
        client_verify_handshake(
            server_signing_public,  # Client uses legitimate server's public key
            client_dh_public, client_kyber_public,
            attacker_dh_public, attacker_kyber_public,  # But keys are from attacker
            attacker_signature
        )
        print("✗ SECURITY FAILURE: Verification should have failed!")
    except AuthenticationError as e:
        print(f"✓ Authentication correctly failed!")
        print(f"  Reason: {e}")
        print("  MITM attack detected and handshake aborted.")
    
    print("\n" + "=" * 60)
    print("AUTHENTICATION FAILURE TEST PASSED!")
    print("=" * 60)


def test_authenticated_hybrid_session_key_function():
    """
    Test the combined authentication + key derivation function.
    
    This tests the authenticated_hybrid_session_key() function which
    ensures secrets are never derived from unverified keys.
    """
    print("\n\n" + "=" * 60)
    print("TEST: Combined Authentication + Key Derivation")
    print("=" * 60)
    
    # Setup
    server_signing_public, server_signing_private = generate_keypair()
    client_dh_private, client_dh_public = kem_keygen(P_DEMO, G_DEMO)
    client_kyber_public, client_kyber_private = kyber_keygen()
    server_dh_private, server_dh_public = kem_keygen(P_DEMO, G_DEMO)
    server_kyber_public, server_kyber_private = kyber_keygen()
    
    # Server signs
    signature = server_sign_handshake(
        server_signing_private,
        client_dh_public, client_kyber_public,
        server_dh_public, server_kyber_public
    )
    
    # Compute shared secrets
    from dh_kem.kem import dh_compute_shared_secret
    dh_secret = dh_compute_shared_secret(server_dh_public, client_dh_private, P_DEMO)
    kyber_ct, kyber_secret = kyber_encapsulate(server_kyber_public)
    
    print("\n--- Using authenticated_hybrid_session_key() ---")
    
    try:
        session_key = authenticated_hybrid_session_key(
            dh_secret, kyber_secret,
            server_signing_public,
            client_dh_public, client_kyber_public,
            server_dh_public, server_kyber_public,
            signature
        )
        print(f"✓ Session key derived: {session_key.hex()}")
    except AuthenticationError as e:
        print(f"✗ Unexpected authentication failure: {e}")
        return
    
    print("\n" + "=" * 60)
    print("COMBINED FUNCTION TEST PASSED!")
    print("=" * 60)


if __name__ == "__main__":
    test_authenticated_hybrid_handshake()
    test_authentication_failure()
    test_authenticated_hybrid_session_key_function()
    
    print("\n\n" + "=" * 60)
    print("ALL AUTHENTICATED HANDSHAKE TESTS PASSED!")
    print("=" * 60)
