"""
BlackRelay Encryptor Module
Provides encryption utilities for secure communications
"""
import os
import base64
import hashlib
import hmac
import time
import json
import logging
from typing import Dict, List, Any, Optional, Union, Tuple, Callable, BinaryIO

# Try to import cryptography modules
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
    from cryptography.hazmat.primitives import hashes, serialization, hmac as crypto_hmac
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False
    
    # Fallback notice
    import warnings
    warnings.warn("Cryptography module not found, using fallback implementations with lower security")


class SymmetricEncryption:
    """Handles symmetric encryption (AES) for secure data transmission"""
    
    @staticmethod
    def generate_key(key_size: int = 256) -> bytes:
        """Generate a random AES key
        
        Args:
            key_size: Size of the key in bits (128, 192, or 256)
            
        Returns:
            The generated key as bytes
        """
        if key_size not in (128, 192, 256):
            raise ValueError("Key size must be 128, 192, or 256 bits")
        return os.urandom(key_size // 8)
    
    @staticmethod
    def encrypt(plaintext: Union[str, bytes], key: bytes) -> Dict[str, bytes]:
        """Encrypt data using AES-GCM mode
        
        Args:
            plaintext: Data to encrypt
            key: AES key
            
        Returns:
            Dictionary containing iv, ciphertext, and tag
        """
        if not HAS_CRYPTOGRAPHY:
            return SymmetricEncryption._fallback_encrypt(plaintext, key)
            
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
            
        iv = os.urandom(12)  # GCM recommended IV size
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()
        
        # Include timestamp for integrity
        aad = str(int(time.time())).encode('utf-8')
        encryptor.authenticate_additional_data(aad)
        
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        return {
            'iv': iv,
            'ciphertext': ciphertext,
            'tag': encryptor.tag,
            'aad': aad  # Store AAD for verification during decryption
        }
    
    @staticmethod
    def decrypt(encrypted_data: Dict[str, bytes], key: bytes) -> bytes:
        """Decrypt AES-GCM encrypted data
        
        Args:
            encrypted_data: Dictionary containing iv, ciphertext, tag, and aad
            key: AES key
            
        Returns:
            Decrypted data as bytes
        """
        if not HAS_CRYPTOGRAPHY:
            return SymmetricEncryption._fallback_decrypt(encrypted_data, key)
            
        try:
            iv = encrypted_data['iv']
            ciphertext = encrypted_data['ciphertext']
            tag = encrypted_data['tag']
            aad = encrypted_data.get('aad', b'')  # AAD might not be present in older messages
            
            decryptor = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, tag),
                backend=default_backend()
            ).decryptor()
            
            # Verify AAD if present
            if aad:
                decryptor.authenticate_additional_data(aad)
                
            return decryptor.update(ciphertext) + decryptor.finalize()
        except Exception as e:
            logging.error(f"Decryption error: {e}")
            raise ValueError("Decryption failed - data may be corrupted or tampered with")
    
    @staticmethod
    def _fallback_encrypt(plaintext: Union[str, bytes], key: bytes) -> Dict[str, bytes]:
        """Fallback encryption when cryptography module is not available
        
        WARNING: This is much less secure than the primary implementation!
        
        Args:
            plaintext: Data to encrypt
            key: Encryption key
            
        Returns:
            Dictionary with encrypted data
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # Create a simple XOR cipher with key and a random IV
        iv = os.urandom(16)
        key_hash = hashlib.sha256(key).digest()
        
        # Extend key to data length
        key_stream = b''
        while len(key_stream) < len(plaintext):
            key_stream += hashlib.sha256(key_hash + iv + str(len(key_stream)).encode()).digest()
        key_stream = key_stream[:len(plaintext)]
        
        # XOR the plaintext with key stream
        ciphertext = bytes(a ^ b for a, b in zip(plaintext, key_stream))
        
        # Create a MAC tag
        mac = hmac.new(key, iv + ciphertext, hashlib.sha256).digest()
        
        return {
            'iv': iv,
            'ciphertext': ciphertext,
            'tag': mac,
            'aad': str(int(time.time())).encode('utf-8')
        }
    
    @staticmethod
    def _fallback_decrypt(encrypted_data: Dict[str, bytes], key: bytes) -> bytes:
        """Fallback decryption when cryptography module is not available
        
        Args:
            encrypted_data: Dictionary with encrypted data
            key: Encryption key
            
        Returns:
            Decrypted data
        """
        iv = encrypted_data['iv']
        ciphertext = encrypted_data['ciphertext']
        tag = encrypted_data['tag']
        
        # Verify MAC tag
        computed_mac = hmac.new