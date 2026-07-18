"""
Test suite for hybrid signature authentication (classical ECDSA + post-quantum Dilithium)

This test validates that both classical and post-quantum signatures work correctly
independently and can be used together for defense-in-depth authentication.
"""

from primitives.authentication.classical import ECDSAP256Engine
from primitives.authentication.quantum import MLDSA44Engine


ecdsa = ECDSAP256Engine()
dilithium_sig = MLDSA44Engine()


def test_ecdsa_signatures():
    """Test classical ECDSA P-256 signature scheme"""
    print("\n" + "=" * 70)
    print("TEST: Classical ECDSA (P-256) Signatures")
    print("=" * 70)
    
    # Test 1: Key generation
    print("\n[TEST 1] ECDSA Key Pair Generation")
    print("-" * 70)
    priv_key, pub_key = ecdsa.keygen()
    print(f"✓ Generated ECDSA key pair")
    print(f"  Public key (first 50 chars): {str(pub_key)[:50]}...")
    print(f"  Private key (first 50 chars): {str(priv_key)[:50]}...")
    
    # Test 2: Sign and verify
    print("\n[TEST 2] ECDSA Sign and Verify (Valid Case)")
    print("-" * 70)
    message = b"Test handshake transcript for ECDSA"
    signature = ecdsa.sign(priv_key, message)
    result = ecdsa.verify(pub_key, message, signature)
    print(f"  Message: {message.decode()}")
    print(f"  Signature (first 32 bytes): {signature[:32].hex()}...")
    print(f"✓ Signature verification: {result}")
    assert result, "ECDSA signature verification failed"
    
    # Test 3: Wrong message
    print("\n[TEST 3] ECDSA Verification with Modified Message")
    print("-" * 70)
    wrong_message = b"Modified handshake transcript"
    result = ecdsa.verify(pub_key, wrong_message, signature)
    print(f"  Original message: {message.decode()}")
    print(f"  Modified message: {wrong_message.decode()}")
    print(f"✗ Verification result (should be False): {result}")
    assert not result, "ECDSA should reject modified message"
    
    # Test 4: Wrong key
    print("\n[TEST 4] ECDSA Verification with Different Key")
    print("-" * 70)
    _, other_pub_key = ecdsa.keygen()
    result = ecdsa.verify(other_pub_key, message, signature)
    print(f"  Original signer vs. different public key")
    print(f"✗ Verification result (should be False): {result}")
    assert not result, "ECDSA should reject different key"
    
    print("\n✓ ECDSA tests PASSED\n")


def test_dilithium_signatures():
    """Test post-quantum Dilithium (ML-DSA-44) signature scheme"""
    print("\n" + "=" * 70)
    print("TEST: Post-Quantum Dilithium (ML-DSA-44) Signatures")
    print("=" * 70)
    
    # Test 1: Key generation
    print("\n[TEST 1] Dilithium Key Pair Generation")
    print("-" * 70)
    priv_key, pub_key = dilithium_sig.keygen()
    print(f"✓ Generated Dilithium key pair")
    print(f"  Public key size: {len(pub_key)} bytes")
    print(f"  Private key size: {len(priv_key)} bytes")
    print(f"  Public key (first 32 bytes): {pub_key[:32].hex()}...")
    
    # Test 2: Sign and verify
    print("\n[TEST 2] Dilithium Sign and Verify (Valid Case)")
    print("-" * 70)
    message = b"Test handshake transcript for Dilithium"
    signature = dilithium_sig.sign(priv_key, message)
    result = dilithium_sig.verify(pub_key, message, signature)
    print(f"  Message: {message.decode()}")
    print(f"  Signature size: {len(signature)} bytes")
    print(f"  Signature (first 32 bytes): {signature[:32].hex()}...")
    print(f"✓ Signature verification: {result}")
    assert result, "Dilithium signature verification failed"
    
    # Test 3: Wrong message
    print("\n[TEST 3] Dilithium Verification with Modified Message")
    print("-" * 70)
    wrong_message = b"Modified handshake transcript"
    result = dilithium_sig.verify(pub_key, wrong_message, signature)
    print(f"  Original message: {message.decode()}")
    print(f"  Modified message: {wrong_message.decode()}")
    print(f"✗ Verification result (should be False): {result}")
    assert not result, "Dilithium should reject modified message"
    
    # Test 4: Wrong key
    print("\n[TEST 4] Dilithium Verification with Different Key")
    print("-" * 70)
    _, other_pub_key = dilithium_sig.keygen()
    result = dilithium_sig.verify(other_pub_key, message, signature)
    print(f"  Original signer vs. different public key")
    print(f"✗ Verification result (should be False): {result}")
    assert not result, "Dilithium should reject different key"
    
    print("\n✓ Dilithium tests PASSED\n")


def test_hybrid_authentication():
    """Test hybrid authentication with both classical ECDSA and post-quantum Dilithium"""
    print("\n" + "=" * 70)
    print("TEST: Dual Signature Hybrid Authentication (ECDSA + Dilithium)")
    print("=" * 70)
    
    # Setup: Generate both key pairs
    print("\n[SETUP] Generate Dual Signature Keys")
    print("-" * 70)
    ecdsa_priv, ecdsa_pub = ecdsa.keygen()
    dilithium_priv, dilithium_pub = dilithium_sig.keygen()
    print(f"✓ Generated ECDSA P-256 key pair")
    print(f"✓ Generated Dilithium ML-DSA-44 key pair")
    
    # Test 1: Both signatures valid
    print("\n[TEST 1] Both Signatures Valid (Defense-in-Depth)")
    print("-" * 70)
    transcript = b"Client X25519: 0x1a2b3c... | Server X25519: 0x4d5e6f..."
    print(f"  Handshake transcript: {transcript.decode()}")
    
    ecdsa_sig = ecdsa.sign(ecdsa_priv, transcript)
    dilithium_sig_val = dilithium_sig.sign(dilithium_priv, transcript)
    print(f"\n✓ ECDSA signature generated ({len(ecdsa_sig)} bytes)")
    print(f"✓ Dilithium signature generated ({len(dilithium_sig_val)} bytes)")
    
    ecdsa_valid = ecdsa.verify(ecdsa_pub, transcript, ecdsa_sig)
    dilithium_valid = dilithium_sig.verify(dilithium_pub, transcript, dilithium_sig_val)
    print(f"\n  ECDSA verification: {ecdsa_valid}")
    print(f"  Dilithium verification: {dilithium_valid}")
    print(f"✓ Hybrid authentication: {ecdsa_valid and dilithium_valid}")
    assert ecdsa_valid and dilithium_valid, "Both signatures must be valid"
    
    # Test 2: ECDSA signature corrupted
    print("\n[TEST 2] Attack: ECDSA Signature Corrupted")
    print("-" * 70)
    corrupted_ecdsa = ecdsa_sig[:-10] + b"corrupted!"
    ecdsa_valid = ecdsa.verify(ecdsa_pub, transcript, corrupted_ecdsa)
    dilithium_valid = dilithium_sig.verify(dilithium_pub, transcript, dilithium_sig_val)
    hybrid_auth_success = ecdsa_valid and dilithium_valid
    print(f"  ECDSA verification (corrupted): {ecdsa_valid}")
    print(f"  Dilithium verification: {dilithium_valid}")
    print(f"✗ Hybrid authentication: {hybrid_auth_success}")
    print(f"  ✓ Attack REJECTED (dual protection works!)")
    assert not hybrid_auth_success, "Hybrid auth should fail with corrupted ECDSA"
    
    # Test 3: Dilithium signature corrupted
    print("\n[TEST 3] Attack: Dilithium Signature Corrupted")
    print("-" * 70)
    corrupted_dilithium = dilithium_sig_val[:-10] + b"corrupted!"
    ecdsa_valid = ecdsa.verify(ecdsa_pub, transcript, ecdsa_sig)
    dilithium_valid = dilithium_sig.verify(dilithium_pub, transcript, corrupted_dilithium)
    hybrid_auth_success = ecdsa_valid and dilithium_valid
    print(f"  ECDSA verification: {ecdsa_valid}")
    print(f"  Dilithium verification (corrupted): {dilithium_valid}")
    print(f"✗ Hybrid authentication: {hybrid_auth_success}")
    print(f"  ✓ Attack REJECTED (dual protection works!)")
    assert not hybrid_auth_success, "Hybrid auth should fail with corrupted Dilithium"
    
    print("\n✓ Hybrid authentication tests PASSED\n")


if __name__ == "__main__":
    test_ecdsa_signatures()
    test_dilithium_signatures()
    test_hybrid_authentication()
    
    print("\n" + "=" * 70)
    print("✓ ALL SIGNATURE TESTS PASSED!")
    print("=" * 70)
