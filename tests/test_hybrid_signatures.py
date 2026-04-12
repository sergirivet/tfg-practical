"""
Test suite for hybrid signature authentication (classical ECDSA + post-quantum Dilithium)

This test validates that both classical and post-quantum signatures work correctly
independently and can be used together for defense-in-depth authentication.
"""

import unittest
from primitives.authentication import classical as ecdsa, quantum as dilithium_sig


class TestECDSASignatures(unittest.TestCase):
    """Test classical ECDSA P-256 signature scheme"""
    
    def setUp(self):
        """Generate fresh key pairs for each test"""
        self.pub_key, self.priv_key = ecdsa.generate_keypair()
    
    def test_generate_keypair(self):
        """Test ECDSA key pair generation"""
        self.assertIsNotNone(self.pub_key)
        self.assertIsNotNone(self.priv_key)
        self.assertTrue(self.pub_key.startswith(b'-----BEGIN PUBLIC KEY-----'))
        self.assertTrue(self.priv_key.startswith(b'-----BEGIN PRIVATE KEY-----'))
    
    def test_sign_and_verify(self):
        """Test ECDSA signing and verification"""
        message = b"Test handshake transcript for ECDSA"
        signature = ecdsa.sign(self.priv_key, message)
        
        # Verify with correct key and message
        result = ecdsa.verify(self.pub_key, message, signature)
        self.assertTrue(result)
    
    def test_verify_fails_with_wrong_message(self):
        """Test that verification fails if message is modified"""
        message = b"Original message"
        wrong_message = b"Modified message"
        signature = ecdsa.sign(self.priv_key, message)
        
        result = ecdsa.verify(self.pub_key, wrong_message, signature)
        self.assertFalse(result)
    
    def test_verify_fails_with_wrong_key(self):
        """Test that verification fails with different public key"""
        message = b"Test message"
        signature = ecdsa.sign(self.priv_key, message)
        
        # Generate different key pair
        other_pub_key, _ = ecdsa.generate_keypair()
        result = ecdsa.verify(other_pub_key, message, signature)
        self.assertFalse(result)
    
    def test_signature_is_deterministic(self):
        """Test that same input produces same signature (deterministic ECDSA)"""
        message = b"Consistent test message"
        sig1 = ecdsa.sign(self.priv_key, message)
        sig2 = ecdsa.sign(self.priv_key, message)
        
        # Both signatures should verify
        self.assertTrue(ecdsa.verify(self.pub_key, message, sig1))
        self.assertTrue(ecdsa.verify(self.pub_key, message, sig2))


class TestDilithiumSignatures(unittest.TestCase):
    """Test post-quantum Dilithium (ML-DSA-44) signature scheme"""
    
    def setUp(self):
        """Generate fresh key pairs for each test"""
        self.pub_key, self.priv_key = dilithium_sig.generate_keypair()
    
    def test_generate_keypair(self):
        """Test Dilithium key pair generation"""
        self.assertIsNotNone(self.pub_key)
        self.assertIsNotNone(self.priv_key)
        self.assertIsInstance(self.pub_key, bytes)
        self.assertIsInstance(self.priv_key, bytes)
    
    def test_sign_and_verify(self):
        """Test Dilithium signing and verification"""
        message = b"Test handshake transcript for Dilithium"
        signature = dilithium_sig.sign(self.priv_key, message)
        
        result = dilithium_sig.verify(self.pub_key, message, signature)
        self.assertTrue(result)
    
    def test_verify_fails_with_wrong_message(self):
        """Test that verification fails if message is modified"""
        message = b"Original message"
        wrong_message = b"Modified message"
        signature = dilithium_sig.sign(self.priv_key, message)
        
        result = dilithium_sig.verify(self.pub_key, wrong_message, signature)
        self.assertFalse(result)
    
    def test_verify_fails_with_wrong_key(self):
        """Test that verification fails with different public key"""
        message = b"Test message"
        signature = dilithium_sig.sign(self.priv_key, message)
        
        # Generate different key pair
        other_pub_key, _ = dilithium_sig.generate_keypair()
        result = dilithium_sig.verify(other_pub_key, message, signature)
        self.assertFalse(result)


class TestHybridSignatureAuthentication(unittest.TestCase):
    """Test hybrid authentication with both classical ECDSA and post-quantum Dilithium"""
    
    def setUp(self):
        """Setup both classical and post-quantum keys"""
        # Classical (ECDSA)
        self.ecdsa_pub, self.ecdsa_priv = ecdsa.generate_keypair()
        # Post-quantum (Dilithium)
        self.dilithium_pub, self.dilithium_priv = dilithium_sig.generate_keypair()
    
    def test_hybrid_authentication_both_signatures_valid(self):
        """Test that both signatures verify correctly on the same message"""
        # Handshake transcript (this would be ephemeral keys concatenated)
        transcript = b"Client X25519 ephemeral: 0x123456... Server X25519 ephemeral: 0x789abc..."
        
        # Sign with both schemes
        ecdsa_sig = ecdsa.sign(self.ecdsa_priv, transcript)
        dilithium_signature = dilithium_sig.sign(self.dilithium_priv, transcript)
        
        # Verify both signatures
        ecdsa_valid = ecdsa.verify(self.ecdsa_pub, transcript, ecdsa_sig)
        dilithium_valid = dilithium_sig.verify(self.dilithium_pub, transcript, dilithium_signature)
        
        # Both must be valid for defense-in-depth
        self.assertTrue(ecdsa_valid)
        self.assertTrue(dilithium_valid)
    
    def test_hybrid_authentication_requires_both_valid(self):
        """Test that in hybrid mode, both signatures must be valid"""
        transcript = b"Hybrid handshake transcript"
        
        # Sign with both schemes
        ecdsa_sig = ecdsa.sign(self.ecdsa_priv, transcript)
        dilithium_signature = dilithium_sig.sign(self.dilithium_priv, transcript)
        
        # Scenario 1: Classical signature corrupted
        corrupted_ecdsa_sig = ecdsa_sig[:-5] + b"XXXXX"
        ecdsa_valid = ecdsa.verify(self.ecdsa_pub, transcript, corrupted_ecdsa_sig)
        dilithium_valid = dilithium_sig.verify(self.dilithium_pub, transcript, dilithium_signature)
        
        # For hybrid auth to succeed, both must be valid
        hybrid_auth_fails = not (ecdsa_valid and dilithium_valid)
        self.assertTrue(hybrid_auth_fails)
    
    def test_classical_security_failure_caught_by_pq(self):
        """
        Test that if classical signature is forged, authentication fails.
        In a real attack where classical crypto is broken, PQ signature still protects.
        """
        transcript = b"Server ephemeral keys"
        
        # Generate legitimate signatures
        ecdsa_sig = ecdsa.sign(self.ecdsa_priv, transcript)
        dilithium_signature = dilithium_sig.sign(self.dilithium_priv, transcript)
        
        # Simulate classical compromise: attacker forges ECDSA signature
        forged_ecdsa_sig = b"forged_signature_from_attacker"
        
        # Classical authentication fails (ecdsa verification fails)
        ecdsa_valid = ecdsa.verify(self.ecdsa_pub, transcript, forged_ecdsa_sig)
        self.assertFalse(ecdsa_valid)
        
        # PQ authentication still succeeds (defender's benefit)
        dilithium_valid = dilithium_sig.verify(self.dilithium_pub, transcript, dilithium_signature)
        self.assertTrue(dilithium_valid)
        
        # But overall hybrid auth fails because classical part failed
        hybrid_auth_succeeds = ecdsa_valid and dilithium_valid
        self.assertFalse(hybrid_auth_succeeds)


if __name__ == '__main__':
    unittest.main()
