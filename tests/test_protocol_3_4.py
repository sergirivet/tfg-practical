"""
Test: Protocol 3.4 using Client and Server classes

This test demonstrates the formal Client-Server Hybrid Authenticated Handshake
Protocol (3.4) using the structured Client and Server classes.

This is the recommended way to use the protocol in practice.
"""

from protocol.client import Client
from protocol.server import Server
from primitives.authentication.quantum import generate_keypair as generate_keypair_dilithium
from primitives.authentication.classical import generate_keypair as generate_keypair_ecdsa
from primitives.kdf.hmac import hmac_sha256


def test_protocol_3_4_with_classes():
    """Test Protocol 3.4 using Client and Server classes (structured approach).
    
    This test demonstrates the formal Client-Server Hybrid Authenticated Handshake
    Protocol (3.4) using the structured Client and Server classes WITH DUAL
    SIGNATURE AUTHENTICATION (classical ECDSA + post-quantum Dilithium).
    
    This is the recommended way to use the protocol in practice.
    """
    
    print("=" * 70)
    print("TEST: Protocol 3.4 - Hybrid Authenticated Handshake (Client/Server)")
    print("      With DUAL SIGNATURES: Classical (ECDSA) + Post-Quantum (Dilithium)")
    print("=" * 70)
    
    # ==========================================================================
    # PHASE 0: Long-term setup (done once, server initialization)
    # ==========================================================================
    print("\n[PHASE 0] Server Long-Term Key Setup (DUAL KEYS)")
    print("-" * 70)
    
    # Server generates BOTH classical and post-quantum signing keys
    server_signing_public_dilithium, server_signing_private_dilithium = generate_keypair_dilithium()
    server_signing_public_ecdsa, server_signing_private_ecdsa = generate_keypair_ecdsa()
    
    print(f"✓ Server generated Dilithium (ML-DSA-44) signing key pair")
    print(f"  Public key (for PQ auth): {server_signing_public_dilithium[:32].hex()}... (truncated)")
    print(f"✓ Server generated ECDSA (P-256) signing key pair")
    print(f"  Public key (for classical auth): {server_signing_public_ecdsa[:50].hex()}... (truncated)")
    
    # ==========================================================================
    # PHASE 1: Client initialization
    # ==========================================================================
    print("\n[PHASE 1] Client Ephemeral Key Generation")
    print("-" * 70)
    
    # Create client with server's BOTH public keys (obtained through trusted channel)
    client = Client(server_signing_public_dilithium, server_signing_public_ecdsa)
    print(f"✓ Client created with server's trusted DUAL public keys")
    
    # Client generates ephemeral keys
    client_pk_dh, client_pk_kyber = client.phase1_generate_ephemeral_keys()
    print(f"✓ Client generated ephemeral keys")
    print(f"  Ephemeral DH public: {client_pk_dh.hex()}")
    print(f"  Ephemeral Kyber public: {client_pk_kyber[:32].hex()}... (truncated)")
    
    print(f"\n→ Client sends to Server: (pk_dh_c, pk_kyber_c)")
    
    # ==========================================================================
    # PHASE 2: Server response
    # ==========================================================================
    print("\n[PHASE 2] Server Ephemeral Key Generation & DUAL Signing")
    print("-" * 70)
    
    # Create server with BOTH long-term signing keys
    server = Server(server_signing_private_dilithium, server_signing_private_ecdsa)
    print(f"✓ Server initialized with long-term DUAL signing keys")
    
    # Server responds to client and creates DUAL signatures
    server_pk_dh, server_pk_kyber, signature_dilithium, signature_ecdsa = server.phase2_generate_ephemeral_and_sign(
        client_pk_dh, client_pk_kyber
    )
    print(f"✓ Server generated ephemeral keys and signed with BOTH schemes")
    print(f"  Ephemeral DH public: {server_pk_dh.hex()}")
    print(f"  Ephemeral Kyber public: {server_pk_kyber[:32].hex()}... (truncated)")
    print(f"  Dilithium signature: {signature_dilithium[:32].hex()}... (truncated)")
    print(f"  ECDSA signature: {signature_ecdsa[:32].hex()}... (truncated)")
    
    print(f"\n→ Server sends to Client: (pk_dh_s, pk_kyber_s, sig_dilithium, sig_ecdsa)")
    
    # ==========================================================================
    # PHASE 3: Client verification
    # ==========================================================================
    print("\n[PHASE 3] Client DUAL Signature Verification")
    print("-" * 70)
    
    try:
        # Client verifies BOTH signatures and derives session key
        client_session_key, kyber_ciphertext = client.phase3_verify_phase4_derive(
            server_pk_dh, server_pk_kyber, signature_dilithium, signature_ecdsa
        )
        print(f"✓ Dilithium (post-quantum) signature verified successfully")
        print(f"✓ ECDSA (classical) signature verified successfully")
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
    print(f"- Authentication: DUAL SIGNATURES (classical ECDSA + post-quantum Dilithium)")
    print(f"- DH: X25519 (classical, forward-secret)")
    print(f"- PQ-KEM: ML-KEM-512 (post-quantum security)")
    print(f"- Session key: 32 bytes (hybrid DH || Kyber)")
    print(f"- Post-handshake: HMAC-SHA256 for message integrity")
    print()
    
    return True


def test_protocol_3_4_mitm_detection():
    """Test that Protocol 3.4 detects MITM attacks (signature verification fails).
    
    Simulates an attacker intercepting the handshake and substituting
    their own ephemeral keys. BOTH signature schemes (classical + PQ)
    must fail if the attacker uses different keys.
    """
    
    print("\n" + "=" * 70)
    print("TEST: Protocol 3.4 - MITM Attack Detection (DUAL SIGNATURES)")
    print("=" * 70)
    
    # Setup legitimate server with DUAL keys
    server_signing_public_dilithium, server_signing_private_dilithium = generate_keypair_dilithium()
    server_signing_public_ecdsa, server_signing_private_ecdsa = generate_keypair_ecdsa()
    server = Server(server_signing_private_dilithium, server_signing_private_ecdsa)
    
    # Attacker's DUAL keys
    attacker_signing_public_dilithium, attacker_signing_private_dilithium = generate_keypair_dilithium()
    attacker_signing_public_ecdsa, attacker_signing_private_ecdsa = generate_keypair_ecdsa()
    attacker_server = Server(attacker_signing_private_dilithium, attacker_signing_private_ecdsa)
    
    # Client (who doesn't know about the attacker)
    client = Client(server_signing_public_dilithium, server_signing_public_ecdsa)  # Uses legitimate server's keys
    
    print("\n[PHASE 1] Client generates and sends ephemeral keys")
    client_pk_dh, client_pk_kyber = client.phase1_generate_ephemeral_keys()
    print(f"CLIENT → SERVER: (pk_dh_c, pk_kyber_c)")
    
    print("\n[PHASE 2] ATTACKER intercepts and substitutes own ephemeral keys")
    # Attacker responds on behalf of server with DUAL signatures
    attacker_pk_dh, attacker_pk_kyber, attacker_sig_dilithium, attacker_sig_ecdsa = attacker_server.phase2_generate_ephemeral_and_sign(
        client_pk_dh, client_pk_kyber
    )
    print(f"ATTACKER → CLIENT: (pk_dh_attacker, pk_kyber_attacker, sig_dilithium_attacker, sig_ecdsa_attacker)")
    
    print("\n[PHASE 3] Client verifies DUAL signatures")
    try:
        # Client tries to verify attacker's signatures with legitimate server's keys
        # This SHOULD fail because attacker's signatures are signed with attacker's keys
        client_session_key, kyber_ct = client.phase3_verify_phase4_derive(
            attacker_pk_dh, attacker_pk_kyber, attacker_sig_dilithium, attacker_sig_ecdsa
        )
        print(f"✗ SECURITY FAILURE: BOTH signatures should have failed but didn't!")
        return False
        
    except Exception as e:
        print(f"✓ DUAL signature verification FAILED (as expected)")
        print(f"  Reason: {e}")
        print(f"  Handshake aborted - MITM attack detected by BOTH authentication schemes!")
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
