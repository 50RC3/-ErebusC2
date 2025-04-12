"""
BlackCypher Encryption Module
Provides cryptographic algorithms and secure communication methods
"""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import os
import base64
from typing import Tuple, Dict, Any, Union, Optional


class SymmetricEncryption:
    """Handles AES encryption for secure data transmission"""
    
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
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
            
        iv = os.urandom(12)  # GCM recommended IV size
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()
        
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        return {
            'iv': iv,
            'ciphertext': ciphertext,
            'tag': encryptor.tag
        }
    
    @staticmethod
    def decrypt(encrypted_data: Dict[str, bytes], key: bytes) -> bytes:
        """Decrypt AES-GCM encrypted data
        
        Args:
            encrypted_data: Dictionary containing iv, ciphertext, and tag
            key: AES key
            
        Returns:
            Decrypted data as bytes
        """
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(encrypted_data['iv'], encrypted_data['tag']),
            backend=default_backend()
        ).decryptor()
        
        return decryptor.update(encrypted_data['ciphertext']) + decryptor.finalize()


class AsymmetricEncryption:
    """Handles RSA encryption for secure key exchange"""
    
    @staticmethod
    def generate_key_pair(key_size: int = 3072) -> Tuple[Any, Any]:
        """Generate an RSA key pair
        
        Args:
            key_size: Size of the key in bits
            
        Returns:
            Tuple containing (private_key, public_key)
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def serialize_public_key(public_key: Any) -> bytes:
        """Convert a public key object to bytes for transmission
        
        Args:
            public_key: RSA public key object
            
        Returns:
            Serialized public key as bytes
        """
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    @staticmethod
    def deserialize_public_key(key_data: bytes) -> Any:
        """Convert bytes to a public key object
        
        Args:
            key_data: Serialized public key bytes
            
        Returns:
            RSA public key object
        """
        return serialization.load_pem_public_key(
            key_data,
            backend=default_backend()
        )
    
    @staticmethod
    def serialize_private_key(private_key: Any, password: Optional[bytes] = None) -> bytes:
        """Convert a private key object to bytes for storage
        
        Args:
            private_key: RSA private key object
            password: Optional password for encryption
            
        Returns:
            Serialized private key as bytes
        """
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(password)
        else:
            encryption_algorithm = serialization.NoEncryption()
            
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
    
    @staticmethod
    def deserialize_private_key(key_data: bytes, password: Optional[bytes] = None) -> Any:
        """Convert bytes to a private key object
        
        Args:
            key_data: Serialized private key bytes
            password: Optional password for decryption
            
        Returns:
            RSA private key object
        """
        return serialization.load_pem_private_key(
            key_data,
            password=password,
            backend=default_backend()
        )
    
    @staticmethod
    def encrypt(plaintext: Union[str, bytes], public_key: Any) -> bytes:
        """Encrypt data using RSA
        
        Args:
            plaintext: Data to encrypt
            public_key: RSA public key object
            
        Returns:
            Encrypted data as bytes
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
            
        return public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    @staticmethod
    def decrypt(ciphertext: bytes, private_key: Any) -> bytes:
        """Decrypt RSA encrypted data
        
        Args:
            ciphertext: Encrypted data
            private_key: RSA private key object
            
        Returns:
            Decrypted data as bytes
        """
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )


class HybridEncryption:
    """Combines symmetric and asymmetric encryption for optimal security and performance"""
    
    @staticmethod
    def encrypt(plaintext: Union[str, bytes], public_key: Any) -> Dict[str, bytes]:
        """Encrypt data using AES with an RSA-encrypted key
        
        Args:
            plaintext: Data to encrypt
            public_key: RSA public key object
            
        Returns:
            Dictionary containing the encrypted key and encrypted data
        """
        # Generate a random AES key
        aes_key = SymmetricEncryption.generate_key()
        
        # Encrypt the data with AES
        encrypted_data = SymmetricEncryption.encrypt(plaintext, aes_key)
        
        # Encrypt the AES key with RSA
        encrypted_key = AsymmetricEncryption.encrypt(aes_key, public_key)
        
        return {
            'encrypted_key': encrypted_key,
            'iv': encrypted_data['iv'],
            'ciphertext': encrypted_data['ciphertext'],
            'tag': encrypted_data['tag']
        }
    
    @staticmethod
    def decrypt(encrypted_package: Dict[str, bytes], private_key: Any) -> bytes:
        """Decrypt data that was encrypted with hybrid encryption
        
        Args:
            encrypted_package: Dictionary with encrypted key and data
            private_key: RSA private key object
            
        Returns:
            Decrypted data as bytes
        """
        # Decrypt the AES key with RSA
        aes_key = AsymmetricEncryption.decrypt(encrypted_package['encrypted_key'], private_key)
        
        # Decrypt the data with AES
        return SymmetricEncryption.decrypt(
            {
                'iv': encrypted_package['iv'],
                'ciphertext': encrypted_package['ciphertext'],
                'tag': encrypted_package['tag']
            },
            aes_key
        )


def encode_bytes_for_transport(data: bytes) -> str:
    """Encode binary data for safe transport in text protocols
    
    Args:
        data: Binary data to encode
        
    Returns:
        Base64-encoded string
    """
    return base64.b64encode(data).decode('utf-8')


def decode_transport_bytes(encoded_data: str) -> bytes:
    """Decode data that was encoded for transport
    
    Args:
        encoded_data: Base64-encoded string
        
    Returns:
        Original binary data
    """
    return base64.b64decode(encoded_data.encode('utf-8'))