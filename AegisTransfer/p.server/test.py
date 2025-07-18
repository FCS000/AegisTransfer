#!/usr/bin/env python3
"""
Test script for encryption/decryption pipeline
"""

import os
from pathlib import Path
from encryption_util import EncryptionManager

TEST_FILE = "test_data.txt"
ENCRYPTED_FILE = "test_data.enc"
ENCRYPTED_KEY = "test_data.enc.key"

def create_test_file():
    """Create a test file with sample data"""
    with open(TEST_FILE, 'w') as f:
        f.write("This is a test message to verify encryption/decryption pipeline.\n")
        f.write("If you can read this after decryption, it works!\n")

def test_encryption():
    """Test full encryption/decryption cycle"""
    print("Setting up test...")
    em = EncryptionManager(rsa_mode=True)
    
    # Create test file
    create_test_file()
    print(f"Created test file: {TEST_FILE}")
    
    # Encrypt
    print("\nEncrypting test file...")
    em.encrypt_file(TEST_FILE, ENCRYPTED_FILE)
    print(f"Encrypted file created: {ENCRYPTED_FILE}")
    print(f"Encryption key saved: {ENCRYPTED_KEY}")
    
    # Decrypt
    print("\nDecrypting test file...")
    with open(ENCRYPTED_KEY, 'rb') as f:
        encrypted_key = f.read()
    
    decrypted_data = em.decrypt_file(ENCRYPTED_FILE, encrypted_key)
    
    # Verify
    print("\nVerifying decrypted content...")
    with open(TEST_FILE, 'rb') as f:
        original_data = f.read()
    
    if decrypted_data == original_data:
        print("✅ Test passed! Decrypted content matches original.")
        print("\nDecrypted content:")
        print(decrypted_data.decode('utf-8'))
    else:
        print("❌ Test failed! Decrypted content does not match original.")
        print(f"Original length: {len(original_data)}")
        print(f"Decrypted length: {len(decrypted_data)}")

if __name__ == "__main__":
    test_encryption()
