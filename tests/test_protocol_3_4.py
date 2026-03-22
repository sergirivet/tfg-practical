"""
Test: Protocol 3.4 using Client and Server classes

This test demonstrates the formal Client-Server Hybrid Authenticated Handshake
Protocol (3.4) using the structured Client and Server classes.

This is the recommended way to use the protocol in practice.
"""

from hybrid.client import Client
from hybrid.server import Server
from signatures.signatures import generate_keypair
from classic.hmac import hmac_sha256


def test_protocol_3_4_with_classes():
    """Test Protocol 3.4 using Client and Server classes (structured approach).
    
    This test follows the formal protocol specification:
    
    PHASE 0: Setup
      Server generates long-term signing key pair
      Client obtains server's public signing key through trusted channel
    
    PHASE 1: Client Initialization
      Client generates ephemeral DH and Kyber keys
      Client sends ephemeral public keys to server
    
    PHASE 2: Server Response
      Server generates ephemeral DH and Kyber keys
      Server signs handshake transcript
      Server sends ephemeral public keys and signature to client
    
    PHASE 3: Client Verification
      Client verifies server's signature using server's long-term public key
      If verification fails: ABORT handshake
    
    PHASE 4: Key Derivation  
      Both parties compute DH shared secret
      Both parties compute Kyber shared secret
      Both parties derive hybrid session key
    """
    
    print("=" * 70)
    print("TEST: Protocol 3.4 - Hybrid Authenticated Handshake (Client/Server)")
    print("=" * 70)
    
    # ==========================================================================
    # PHASE 0: Long-term setup (done once, server initialization)
    # ==========================================================================
    print("\n[PHASE 0] Server Long-Term Key Setup")
    print("-" * 70)
    
    server_signing_public, server_signing_private = generate_keypair()
    print(f"✓ Server generated long-term signing key pair")
    print(f"  Public key (distributed via PKI): {server_signing_public[:32].hex()}... (truncated)")
    
    # ==========================================================================
    # PHASE 1: Client initialization
    # ==========================================================================
    print("\n[PHASE 1] Client Ephemeral Key Generation")
    print("-" * 70)
    
    # Create client with server's public key (obtained through trusted channel)
    client = Client(server_signing_public)
    print(f"✓ Client created with server's trusted public key")
    
    # Client generates ephemeral keys
    client_pk_dh, client_pk_kyber = client.phase1_generate_ephemeral_keys()
    print(f"✓ Client generated ephemeral keys")
    print(f"  Ephemeral DH public: {client_pk_dh.hex()}")
    print(f"  Ephemeral Kyber public: {client_pk_kyber[:32].hex()}... (truncated)")
    
    print(f"\n→ Client sends to Server: (pk_dh_c, pk_kyber_c)")
    
    # ==========================================================================
    # PHASE 2: Server response
    # ==========================================================================
    print("\n[PHASE 2] Server Ephemeral Key Generation & Signing")
    print("-" * 70)
    
    # Create server with its long-term signing key
    server = Server(server_signing_private)
    print(f"✓ Server initialized with long-term signing key")
    
    # Server responds to client
    server_pk_dh, server_pk_kyber, signature = server.phase2_generate_ephemeral_and_sign(
        client_pk_dh, client_pk_kyber
    )
    print(f"✓ Server generated ephemeral keys and signed transcript")
    print(f"  Ephemeral DH public: {server_pk_dh.hex()}")
    print(f"  Ephemeral Kyber public: {server_pk_kyber[:32].hex()}... (truncated)")
    print(f"  Signature: {signature[:32].hex()}... (truncated)")
    
    print(f"\n→ Server sends to Client: (pk_dh_s, pk_kyber_s, signature)")
    
    # ==========================================================================
    # PHASE 3: Client verification
    # ==========================================================================
    print("\n[PHASE 3] Client Signature Verification")
    print("-" * 70)
    
    try:
        # Client verifies signature and derives session key
        client_session_key, kyber_ciphertext = client.phase3_verify_phase4_derive(
            server_pk_dh, server_pk_kyber, signature
        )
        print(f"✓ Server signature verified successfully")
        print(f"✓ Client derived session key: {client_session_key.hex()}")
        print(f"≈ Kyber ciphertext for server: {kyber_ciphertext[:32].hex()}... (truncated)")
        
    except Exception as e:
        print(f"✗ Signature verification failed: {e}")
        print(f"  Handshake aborted - MITM attack detected!")
        return False
    
    print(f"\n→ Client sends to Server: kyber_ciphertext")
    
    # ==========================================================================
    # PHASE 4: Server key derivation
    # ==========================================================================
    print("\n[PHASE 4] Server Shared Secret Derivation")
    print("-" * 70)
    
    server_session_key = server.phase4_derive_session_key(client_pk_dh, kyber_ciphertext)
    print(f"✓ Server computed shared secrets and derived session key")
    print(f"  Session key: {server_session_key.hex()}")
    
    # ==========================================================================
    # Verification: Session keys must match
    # ==========================================================================
    print("\n" + "=" * 70)
    print("VERIFICATION")
    print("=" * 70)
    
    if client_session_key == server_session_key:
        print(f"✓ Client and Server session keys MATCH")
        print(f"  Key: {client_session_key.hex()}")
    else:
        print(f"✗ Session keys DO NOT match - ERROR!")
        return False
    
    # ==========================================================================
    # Post-Handshake: HMAC message authentication
    # ==========================================================================
    print("\n[POST-HANDSHAKE] Message Authentication with HMAC-SHA256")
    print("-" * 70)
    
    message = b"Authenticated message from client"
    client_tag = hmac_sha256(client_session_key, message)
    server_tag = hmac_sha256(server_session_key, message)
    
    if client_tag == server_tag:
        print(f"✓ HMAC tags match - message integrity verified")
        print(f"  Message: {message.decode()}")
        print(f"  HMAC: {client_tag.hex()}")
    else:
        print(f"✗ HMAC verification failed")
        return False
    
    print("\n" + "=" * 70)
    print("✓ PROTOCOL 3.4 TEST PASSED!")
    print("=" * 70)
    print()
    print("Summary:")
    print(f"- Handshake: AUTHENTICATED (ML-DSA-44 signature verified)")
    print(f"- DH: X25519 (classical, forward-secret)")
    print(f"- PQ-KEM: ML-KEM-512 (post-quantum security)")
    print(f"- Session key: 32 bytes (hybrid DH || Kyber)")
    print(f"- Post-handshake: HMAC-SHA256 for message integrity")
    print()
    
    return True


def test_protocol_3_4_mitm_detection():
    """Test that Protocol 3.4 detects MITM attacks (signature verification fails).
    
    Simulates an attacker intercepting the handshake and substituting
    their own ephemeral keys. The signature verification should fail.
    """
    
    print("\n" + "=" * 70)
    print("TEST: Protocol 3.4 - MITM Attack Detection")
    print("=" * 70)
    
    # Setup legitimate server
    server_signing_public, server_signing_private = generate_keypair()
    server = Server(server_signing_private)
    
    # Attacker's keys
    attacker_signing_public, attacker_signing_private = generate_keypair()
    attacker_server = Server(attacker_signing_private)
    
    # Client (who doesn't know about the attacker)
    client = Client(server_signing_public)  # Uses legitimate server's key
    
    print("\n[PHASE 1] Client generates and sends ephemeral keys")
    client_pk_dh, client_pk_kyber = client.phase1_generate_ephemeral_keys()
    print(f"CLIENT → SERVER: (pk_dh_c, pk_kyber_c)")
    
    print("\n[PHASE 2] ATTACKER intercepts and substitutes own ephemeral keys")
    # Attacker responds on behalf of server
    attacker_pk_dh, attacker_pk_kyber, attacker_sig = attacker_server.phase2_generate_ephemeral_and_sign(
        client_pk_dh, client_pk_kyber
    )
    print(f"ATTACKER → CLIENT: (pk_dh_attacker, pk_kyber_attacker, sig_attacker)")
    
    print("\n[PHASE 3] Client verifies signature")
    try:
        # Client tries to verify attacker's signature with legitimate server's key
        # This SHOULD fail because attacker's signature is signed with attacker's key
        client_session_key, kyber_ct = client.phase3_verify_phase4_derive(
            attacker_pk_dh, attacker_pk_kyber, attacker_sig
        )
        print(f"✗ SECURITY FAILURE: Signature should have failed but didn't!")
        return False
        
    except Exception as e:
        print(f"✓ Signature verification FAILED (as expected)")
        print(f"  Reason: {e}")
        print(f"  Handshake aborted - MITM attack detected!")
        return True


if __name__ == "__main__":
    success_1 = test_protocol_3_4_with_classes()
    success_2 = test_protocol_3_4_mitm_detection()
    
    if success_1 and success_2:
        print("\n" + "=" * 70)
        print("ALL PROTOCOL 3.4 TESTS PASSED!")
        print("=" * 70)
    else:
        print("\nSome tests failed!")
        exit(1)
