"""
Test: Protocol 3.4 using Client and Server classes

This test demonstrates the formal Client-Server Hybrid Authenticated Handshake
Protocol (3.4) using the structured Client and Server classes.

This is the recommended way to use the protocol in practice.
"""

import pytest

from primitives.authentication.hybrid import HybridSignatureEngine
from primitives.kem.hybrid import HybridKEMEngine
from protocol.client import Client
from protocol.server import Server
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
    
    kem_engine = HybridKEMEngine()
    signature_engine = HybridSignatureEngine()

    # Server generates the hybrid signing key pair through the injected engine.
    server_signing_private, server_signing_public = signature_engine.keygen()
    
    print(f"✓ Server generated hybrid signing key pair")
    print(f"  Public key blob: {server_signing_public[:32].hex()}... (truncated)")
    
    # ==========================================================================
    # PHASE 1: Client initialization
    # ==========================================================================
    print("\n[PHASE 1] Client Ephemeral Key Generation")
    print("-" * 70)
    
    # Create client with server's BOTH public keys (obtained through trusted channel)
    client = Client(server_signing_public, kem_engine, signature_engine)
    print(f"✓ Client created with server's trusted public key blob")
    
    # Client generates ephemeral keys
    client_public_key = client.phase1_generate_ephemeral_keys()
    print(f"✓ Client generated ephemeral keys")
    print(f"  Client hello blob: {client_public_key.hex()}")
    
    print(f"\n→ Client sends to Server: client_hello_blob")
    
    # ==========================================================================
    # PHASE 2: Server response
    # ==========================================================================
    print("\n[PHASE 2] Server Ephemeral Key Generation & DUAL Signing")
    print("-" * 70)
    
    # Create server with BOTH long-term signing keys
    server = Server(server_signing_private, kem_engine, signature_engine)
    print(f"✓ Server initialized with long-term hybrid signing key")
    
    # Server responds to client with a ciphertext and creates a hybrid signature blob.
    server_ciphertext, signature_blob = server.phase2_generate_ephemeral_and_sign(client_public_key)
    print(f"✓ Server encapsulated the hybrid secret and signed the transcript")
    print(f"  Server response blob: {server_ciphertext[:32].hex()}... (truncated)")
    print(f"  Signature blob: {signature_blob[:32].hex()}... (truncated)")
    
    print(f"\n→ Server sends to Client: (server_response_blob, signature_blob)")
    
    # ==========================================================================
    # PHASE 3: Client verification
    # ==========================================================================
    print("\n[PHASE 3] Client DUAL Signature Verification")
    print("-" * 70)
    
    try:
        # Client verifies BOTH signatures and derives session key
        client_session_key = client.phase3_verify_phase4_derive(server_ciphertext, signature_blob)
        print(f"✓ Hybrid signature verified successfully")
        print(f"✓ Client derived session key: {client_session_key.hex()}")
        
    except Exception as e:
        pytest.fail(f"Signature verification failed unexpectedly: {e}")
    
    # ==========================================================================
    # PHASE 4: Server key derivation
    # ==========================================================================
    print("\n[PHASE 4] Server Shared Secret Derivation")
    print("-" * 70)
    
    server_session_key = server.phase4_derive_session_key(client_public_key)
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
        pytest.fail("Session keys do not match")
    
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
        pytest.fail("HMAC verification failed")
    
    print("\n" + "=" * 70)
    print("✓ PROTOCOL 3.4 TEST PASSED!")
    print("=" * 70)
    print()
    print("Summary:")
    print(f"- Authentication: hybrid signature blob (classical + post-quantum)")
    print(f"- KEM: hybrid packed key exchange (classical + post-quantum)")
    print(f"- Session key: 32 bytes derived inside the KEM engine")
    print(f"- Post-handshake: HMAC-SHA256 for message integrity")
    print()

    assert client_session_key == server_session_key
    assert client_tag == server_tag


def test_protocol_3_4_mitm_detection():
    """Test that Protocol 3.4 detects MITM attacks (signature verification fails).
    
    Simulates an attacker intercepting the handshake and substituting
    their own ephemeral keys. BOTH signature schemes (classical + PQ)
    must fail if the attacker uses different keys.
    """
    
    print("\n" + "=" * 70)
    print("TEST: Protocol 3.4 - MITM Attack Detection (DUAL SIGNATURES)")
    print("=" * 70)
    
    kem_engine = HybridKEMEngine()
    signature_engine = HybridSignatureEngine()

    # Setup legitimate server with hybrid keys
    server_signing_private, server_signing_public = signature_engine.keygen()
    server = Server(server_signing_private, kem_engine, signature_engine)
    
    # Attacker's hybrid keys
    attacker_signature_engine = HybridSignatureEngine()
    attacker_signing_private, attacker_signing_public = attacker_signature_engine.keygen()
    attacker_server = Server(attacker_signing_private, kem_engine, attacker_signature_engine)
    
    # Client (who doesn't know about the attacker)
    client = Client(server_signing_public, kem_engine, signature_engine)  # Uses legitimate server's keys
    
    print("\n[PHASE 1] Client generates and sends ephemeral keys")
    client_public_key = client.phase1_generate_ephemeral_keys()
    print(f"CLIENT → SERVER: client_hello_blob")
    
    print("\n[PHASE 2] ATTACKER intercepts and substitutes own ephemeral keys")
    # Attacker responds on behalf of server with a hybrid signature blob
    attacker_ciphertext, attacker_signature = attacker_server.phase2_generate_ephemeral_and_sign(client_public_key)
    print(f"ATTACKER → CLIENT: (server_response_blob, signature_blob)")
    
    print("\n[PHASE 3] Client verifies DUAL signatures")
    # Client tries to verify attacker's signatures with legitimate server's keys.
    # This SHOULD fail because attacker's signatures are signed with attacker's keys.
    with pytest.raises(Exception):
        client_session_key = client.phase3_verify_phase4_derive(attacker_ciphertext, attacker_signature)

    print(f"✓ Hybrid signature verification FAILED (as expected)")
    print(f"  Handshake aborted - MITM attack detected by the authentication layer!")


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
