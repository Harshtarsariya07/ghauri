#!/usr/bin/python3
# -*- coding: utf-8 -*-
# pylint: disable=R,W,E,C

"""
Encryption/Decryption utilities for handling AES encrypted parameters
Based on JavaScript CryptoJS implementation
"""

import base64
import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad


class AesUtil:
    """
    AES encryption utility matching JavaScript CryptoJS implementation
    """
    
    def __init__(self, key_size=128, iteration_count=1000):
        """
        Initialize AES utility
        
        Args:
            key_size: Key size in bits (default 128)
            iteration_count: PBKDF2 iteration count (default 1000)
        """
        self.key_size = key_size // 32  # Convert bits to 32-bit words
        self.iteration_count = iteration_count
    
    def generate_key(self, salt, pass_phrase):
        """
        Generate encryption key using PBKDF2
        
        Args:
            salt: Salt in hex format
            pass_phrase: Passphrase string
            
        Returns:
            Encryption key bytes
        """
        # Convert hex salt to bytes
        salt_bytes = bytes.fromhex(salt)
        # Generate key using PBKDF2
        key = PBKDF2(
            pass_phrase.encode('utf-8'),
            salt_bytes,
            dkLen=self.key_size * 4,  # Convert 32-bit words to bytes
            count=self.iteration_count
        )
        return key
    
    def encrypt(self, plain_text, pass_phrase):
        """
        Encrypt plain text using AES
        
        Args:
            plain_text: Text to encrypt
            pass_phrase: Passphrase for encryption
            
        Returns:
            Base64 encoded encrypted string in format: iv::salt::ciphertext
        """
        # Generate random IV (16 bytes = 128 bits)
        iv = os.urandom(16)
        iv_hex = iv.hex()
        
        # Generate random salt (16 bytes = 128 bits)
        salt = os.urandom(16)
        salt_hex = salt.hex()
        
        # Generate encryption key
        key = self.generate_key(salt_hex, pass_phrase)
        
        # Create AES cipher
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Pad plaintext to block size
        padded_text = pad(plain_text.encode('utf-8'), AES.block_size)
        
        # Encrypt
        encrypted = cipher.encrypt(padded_text)
        
        # Encode ciphertext to base64
        ciphertext_b64 = base64.b64encode(encrypted).decode('utf-8')
        
        # Combine: iv::salt::ciphertext
        combined = f"{iv_hex}::{salt_hex}::{ciphertext_b64}"
        
        # Base64 encode the entire string
        return base64.b64encode(combined.encode('utf-8')).decode('utf-8')
    
    def decrypt(self, salt, iv, pass_phrase, cipher_text):
        """
        Decrypt cipher text using AES
        
        Args:
            salt: Salt in hex format
            iv: Initialization vector in hex format
            pass_phrase: Passphrase for decryption
            cipher_text: Base64 encoded ciphertext
            
        Returns:
            Decrypted plain text string
        """
        # Generate decryption key
        key = self.generate_key(salt, pass_phrase)
        
        # Decode ciphertext from base64
        ciphertext_bytes = base64.b64decode(cipher_text)
        
        # Convert IV from hex to bytes
        iv_bytes = bytes.fromhex(iv)
        
        # Create AES cipher
        cipher = AES.new(key, AES.MODE_CBC, iv_bytes)
        
        # Decrypt
        decrypted = cipher.decrypt(ciphertext_bytes)
        
        # Unpad
        plaintext = unpad(decrypted, AES.block_size)
        
        return plaintext.decode('utf-8')
    
    def decrypt_from_encoded(self, pass_phrase, encoded_text):
        """
        Decrypt from base64 encoded string containing iv::salt::ciphertext
        
        Args:
            pass_phrase: Passphrase for decryption
            encoded_text: Base64 encoded string containing iv::salt::ciphertext
            
        Returns:
            Decrypted plain text string
        """
        # Decode base64
        decoded = base64.b64decode(encoded_text).decode('utf-8')
        
        # Split by ::
        parts = decoded.split("::")
        if len(parts) != 3:
            raise ValueError("Invalid encrypted format. Expected iv::salt::ciphertext")
        
        iv = parts[0]
        salt = parts[1]
        ciphertext = parts[2]
        
        return self.decrypt(salt, iv, pass_phrase, ciphertext)


def decrypt_parameter(encrypted_value, secret_key):
    """
    Decrypt a parameter value using the provided secret key
    
    Args:
        encrypted_value: Base64 encoded encrypted value
        secret_key: Secret key for decryption
        
    Returns:
        Decrypted plain text value
    """
    aes_util = AesUtil(128, 1000)
    return aes_util.decrypt_from_encoded(secret_key, encrypted_value)


def encrypt_parameter(plain_value, secret_key):
    """
    Encrypt a parameter value using the provided secret key
    
    Args:
        plain_value: Plain text value to encrypt
        secret_key: Secret key for encryption
        
    Returns:
        Base64 encoded encrypted value
    """
    aes_util = AesUtil(128, 1000)
    return aes_util.encrypt(plain_value, secret_key)

