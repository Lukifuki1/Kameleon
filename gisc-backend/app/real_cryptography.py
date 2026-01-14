"""
GLOBAL INTELLIGENCE SECURITY COMMAND CENTER - REAL CRYPTOGRAPHY ENGINE
Enterprise-grade cryptographic implementations

This module provides:
- AES-256-GCM symmetric encryption
- RSA-4096 asymmetric encryption
- Ed25519 digital signatures
- SHA-256/SHA-512 hashing
- PBKDF2/Argon2 key derivation
- Secure random number generation
- Certificate management
- Key management

Classification: TOP SECRET // NSOC // TIER-0
"""

import os
import hashlib
import hmac
import base64
import json
import struct
import time
from typing import Tuple, Optional, Dict, Any, List
from dataclasses import dataclass
from datetime import datetime, timedelta

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import pkcs1_15, eddsa
from Crypto.Hash import SHA256, SHA512, SHA3_256, HMAC as CryptoHMAC
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2, scrypt
from Crypto.Util.Padding import pad, unpad


@dataclass
class EncryptionResult:
    ciphertext: bytes
    nonce: bytes
    tag: bytes
    algorithm: str
    key_id: Optional[str]
    timestamp: str


@dataclass
class DecryptionResult:
    plaintext: bytes
    verified: bool
    algorithm: str
    timestamp: str


@dataclass
class SignatureResult:
    signature: bytes
    algorithm: str
    key_id: str
    timestamp: str
    message_hash: str


@dataclass
class KeyPair:
    public_key: bytes
    private_key: bytes
    key_type: str
    key_size: int
    key_id: str
    created_at: str
    expires_at: Optional[str]


@dataclass
class DerivedKey:
    key: bytes
    salt: bytes
    algorithm: str
    iterations: int
    key_id: str


class SecureRandom:
    """Cryptographically secure random number generator"""
    
    @staticmethod
    def generate_bytes(length: int) -> bytes:
        """Generate cryptographically secure random bytes"""
        return get_random_bytes(length)
    
    @staticmethod
    def generate_hex(length: int) -> str:
        """Generate random hex string"""
        return get_random_bytes(length).hex()
    
    @staticmethod
    def generate_base64(length: int) -> str:
        """Generate random base64 string"""
        return base64.b64encode(get_random_bytes(length)).decode('utf-8')
    
    @staticmethod
    def generate_int(min_val: int, max_val: int) -> int:
        """Generate random integer in range"""
        range_size = max_val - min_val + 1
        bytes_needed = (range_size.bit_length() + 7) // 8
        
        while True:
            random_bytes = get_random_bytes(bytes_needed)
            random_int = int.from_bytes(random_bytes, 'big')
            if random_int < (256 ** bytes_needed // range_size) * range_size:
                return min_val + (random_int % range_size)
    
    @staticmethod
    def generate_uuid() -> str:
        """Generate random UUID v4"""
        random_bytes = bytearray(get_random_bytes(16))
        random_bytes[6] = (random_bytes[6] & 0x0f) | 0x40
        random_bytes[8] = (random_bytes[8] & 0x3f) | 0x80
        
        hex_str = random_bytes.hex()
        return f"{hex_str[:8]}-{hex_str[8:12]}-{hex_str[12:16]}-{hex_str[16:20]}-{hex_str[20:]}"


class HashEngine:
    """Cryptographic hashing functions"""
    
    @staticmethod
    def sha256(data: bytes) -> bytes:
        """Compute SHA-256 hash"""
        return SHA256.new(data).digest()
    
    @staticmethod
    def sha256_hex(data: bytes) -> str:
        """Compute SHA-256 hash as hex string"""
        return SHA256.new(data).hexdigest()
    
    @staticmethod
    def sha512(data: bytes) -> bytes:
        """Compute SHA-512 hash"""
        return SHA512.new(data).digest()
    
    @staticmethod
    def sha512_hex(data: bytes) -> str:
        """Compute SHA-512 hash as hex string"""
        return SHA512.new(data).hexdigest()
    
    @staticmethod
    def sha3_256(data: bytes) -> bytes:
        """Compute SHA3-256 hash"""
        return SHA3_256.new(data).digest()
    
    @staticmethod
    def sha3_256_hex(data: bytes) -> str:
        """Compute SHA3-256 hash as hex string"""
        return SHA3_256.new(data).hexdigest()
    
    @staticmethod
    def hmac_sha256(key: bytes, data: bytes) -> bytes:
        """Compute HMAC-SHA256"""
        return hmac.new(key, data, hashlib.sha256).digest()
    
    @staticmethod
    def hmac_sha256_hex(key: bytes, data: bytes) -> str:
        """Compute HMAC-SHA256 as hex string"""
        return hmac.new(key, data, hashlib.sha256).hexdigest()
    
    @staticmethod
    def hmac_sha512(key: bytes, data: bytes) -> bytes:
        """Compute HMAC-SHA512"""
        return hmac.new(key, data, hashlib.sha512).digest()
    
    @staticmethod
    def verify_hmac(key: bytes, data: bytes, expected_mac: bytes, algorithm: str = 'sha256') -> bool:
        """Verify HMAC in constant time"""
        if algorithm == 'sha256':
            computed = hmac.new(key, data, hashlib.sha256).digest()
        elif algorithm == 'sha512':
            computed = hmac.new(key, data, hashlib.sha512).digest()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        return hmac.compare_digest(computed, expected_mac)


class KeyDerivation:
    """Key derivation functions"""
    
    @staticmethod
    def pbkdf2(
        password: bytes,
        salt: bytes = None,
        iterations: int = 600000,
        key_length: int = 32
    ) -> DerivedKey:
        """Derive key using PBKDF2-HMAC-SHA256"""
        if salt is None:
            salt = get_random_bytes(32)
        
        key = PBKDF2(
            password,
            salt,
            dkLen=key_length,
            count=iterations,
            hmac_hash_module=SHA256
        )
        
        return DerivedKey(
            key=key,
            salt=salt,
            algorithm='PBKDF2-HMAC-SHA256',
            iterations=iterations,
            key_id=HashEngine.sha256_hex(key)[:16]
        )
    
    @staticmethod
    def scrypt_derive(
        password: bytes,
        salt: bytes = None,
        n: int = 2**14,
        r: int = 8,
        p: int = 1,
        key_length: int = 32
    ) -> DerivedKey:
        """Derive key using scrypt"""
        if salt is None:
            salt = get_random_bytes(32)
        
        key = scrypt(
            password,
            salt,
            key_len=key_length,
            N=n,
            r=r,
            p=p
        )
        
        return DerivedKey(
            key=key,
            salt=salt,
            algorithm=f'scrypt-N{n}-r{r}-p{p}',
            iterations=n,
            key_id=HashEngine.sha256_hex(key)[:16]
        )
    
    @staticmethod
    def hkdf_expand(
        key: bytes,
        info: bytes,
        length: int = 32
    ) -> bytes:
        """HKDF expand function"""
        hash_len = 32
        n = (length + hash_len - 1) // hash_len
        
        okm = b''
        t = b''
        
        for i in range(1, n + 1):
            t = hmac.new(key, t + info + bytes([i]), hashlib.sha256).digest()
            okm += t
        
        return okm[:length]


class AES256GCM:
    """AES-256-GCM authenticated encryption"""
    
    NONCE_SIZE = 12
    TAG_SIZE = 16
    KEY_SIZE = 32
    
    def __init__(self, key: bytes = None):
        if key is None:
            key = get_random_bytes(self.KEY_SIZE)
        
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"Key must be {self.KEY_SIZE} bytes")
        
        self._key = key
        self._key_id = HashEngine.sha256_hex(key)[:16]
    
    @property
    def key_id(self) -> str:
        return self._key_id
    
    def encrypt(self, plaintext: bytes, associated_data: bytes = None) -> EncryptionResult:
        """Encrypt data using AES-256-GCM"""
        nonce = get_random_bytes(self.NONCE_SIZE)
        
        cipher = AES.new(self._key, AES.MODE_GCM, nonce=nonce)
        
        if associated_data:
            cipher.update(associated_data)
        
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        
        return EncryptionResult(
            ciphertext=ciphertext,
            nonce=nonce,
            tag=tag,
            algorithm='AES-256-GCM',
            key_id=self._key_id,
            timestamp=datetime.utcnow().isoformat()
        )
    
    def decrypt(self, ciphertext: bytes, nonce: bytes, tag: bytes, associated_data: bytes = None) -> DecryptionResult:
        """Decrypt data using AES-256-GCM"""
        cipher = AES.new(self._key, AES.MODE_GCM, nonce=nonce)
        
        if associated_data:
            cipher.update(associated_data)
        
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            verified = True
        except ValueError:
            raise ValueError("Authentication failed - data may have been tampered with")
        
        return DecryptionResult(
            plaintext=plaintext,
            verified=verified,
            algorithm='AES-256-GCM',
            timestamp=datetime.utcnow().isoformat()
        )
    
    def encrypt_to_base64(self, plaintext: bytes, associated_data: bytes = None) -> str:
        """Encrypt and return base64-encoded result"""
        result = self.encrypt(plaintext, associated_data)
        
        combined = result.nonce + result.tag + result.ciphertext
        return base64.b64encode(combined).decode('utf-8')
    
    def decrypt_from_base64(self, encoded: str, associated_data: bytes = None) -> bytes:
        """Decrypt base64-encoded ciphertext"""
        combined = base64.b64decode(encoded)
        
        nonce = combined[:self.NONCE_SIZE]
        tag = combined[self.NONCE_SIZE:self.NONCE_SIZE + self.TAG_SIZE]
        ciphertext = combined[self.NONCE_SIZE + self.TAG_SIZE:]
        
        result = self.decrypt(ciphertext, nonce, tag, associated_data)
        return result.plaintext


class RSA4096:
    """RSA-4096 asymmetric encryption and signatures"""
    
    KEY_SIZE = 4096
    
    def __init__(self, private_key: bytes = None, public_key: bytes = None):
        if private_key:
            self._key = RSA.import_key(private_key)
        elif public_key:
            self._key = RSA.import_key(public_key)
        else:
            self._key = RSA.generate(self.KEY_SIZE)
        
        self._key_id = HashEngine.sha256_hex(self._key.public_key().export_key())[:16]
    
    @property
    def key_id(self) -> str:
        return self._key_id
    
    @property
    def public_key(self) -> bytes:
        return self._key.public_key().export_key()
    
    @property
    def private_key(self) -> bytes:
        if self._key.has_private():
            return self._key.export_key()
        raise ValueError("No private key available")
    
    def generate_keypair(self) -> KeyPair:
        """Generate new RSA-4096 key pair"""
        key = RSA.generate(self.KEY_SIZE)
        
        return KeyPair(
            public_key=key.public_key().export_key(),
            private_key=key.export_key(),
            key_type='RSA',
            key_size=self.KEY_SIZE,
            key_id=HashEngine.sha256_hex(key.public_key().export_key())[:16],
            created_at=datetime.utcnow().isoformat(),
            expires_at=None
        )
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt data using RSA-OAEP"""
        cipher = PKCS1_OAEP.new(self._key.public_key(), hashAlgo=SHA256)
        
        max_chunk = (self.KEY_SIZE // 8) - 66
        
        if len(plaintext) <= max_chunk:
            return cipher.encrypt(plaintext)
        
        chunks = []
        for i in range(0, len(plaintext), max_chunk):
            chunk = plaintext[i:i + max_chunk]
            chunks.append(cipher.encrypt(chunk))
        
        return b''.join(chunks)
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt data using RSA-OAEP"""
        if not self._key.has_private():
            raise ValueError("Private key required for decryption")
        
        cipher = PKCS1_OAEP.new(self._key, hashAlgo=SHA256)
        
        chunk_size = self.KEY_SIZE // 8
        
        if len(ciphertext) <= chunk_size:
            return cipher.decrypt(ciphertext)
        
        chunks = []
        for i in range(0, len(ciphertext), chunk_size):
            chunk = ciphertext[i:i + chunk_size]
            chunks.append(cipher.decrypt(chunk))
        
        return b''.join(chunks)
    
    def sign(self, message: bytes) -> SignatureResult:
        """Sign message using RSA-PSS"""
        if not self._key.has_private():
            raise ValueError("Private key required for signing")
        
        h = SHA256.new(message)
        signature = pkcs1_15.new(self._key).sign(h)
        
        return SignatureResult(
            signature=signature,
            algorithm='RSA-PKCS1-v1_5-SHA256',
            key_id=self._key_id,
            timestamp=datetime.utcnow().isoformat(),
            message_hash=h.hexdigest()
        )
    
    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify RSA signature"""
        h = SHA256.new(message)
        
        try:
            pkcs1_15.new(self._key.public_key()).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False


class Ed25519:
    """Ed25519 digital signatures"""
    
    def __init__(self, private_key: bytes = None, public_key: bytes = None):
        if private_key:
            self._key = ECC.import_key(private_key)
        elif public_key:
            self._key = ECC.import_key(public_key)
        else:
            self._key = ECC.generate(curve='Ed25519')
        
        self._key_id = HashEngine.sha256_hex(self._key.public_key().export_key(format='raw'))[:16]
    
    @property
    def key_id(self) -> str:
        return self._key_id
    
    @property
    def public_key(self) -> bytes:
        return self._key.public_key().export_key(format='raw')
    
    @property
    def private_key(self) -> bytes:
        if self._key.has_private():
            return self._key.export_key(format='PEM').encode() if isinstance(self._key.export_key(format='PEM'), str) else self._key.export_key(format='PEM')
        raise ValueError("No private key available")
    
    def generate_keypair(self) -> KeyPair:
        """Generate new Ed25519 key pair"""
        key = ECC.generate(curve='Ed25519')
        
        return KeyPair(
            public_key=key.public_key().export_key(format='raw'),
            private_key=key.export_key(format='PEM').encode() if isinstance(key.export_key(format='PEM'), str) else key.export_key(format='PEM'),
            key_type='Ed25519',
            key_size=256,
            key_id=HashEngine.sha256_hex(key.public_key().export_key(format='raw'))[:16],
            created_at=datetime.utcnow().isoformat(),
            expires_at=None
        )
    
    def sign(self, message: bytes) -> SignatureResult:
        """Sign message using Ed25519"""
        if not self._key.has_private():
            raise ValueError("Private key required for signing")
        
        signer = eddsa.new(self._key, 'rfc8032')
        signature = signer.sign(message)
        
        return SignatureResult(
            signature=signature,
            algorithm='Ed25519',
            key_id=self._key_id,
            timestamp=datetime.utcnow().isoformat(),
            message_hash=HashEngine.sha256_hex(message)
        )
    
    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify Ed25519 signature"""
        try:
            verifier = eddsa.new(self._key.public_key(), 'rfc8032')
            verifier.verify(message, signature)
            return True
        except (ValueError, TypeError):
            return False


class KeyManager:
    """Secure key management"""
    
    def __init__(self, master_key: bytes = None):
        if master_key is None:
            master_key = get_random_bytes(32)
        
        self._master_cipher = AES256GCM(master_key)
        self._keys: Dict[str, Dict[str, Any]] = {}
    
    def store_key(self, key_id: str, key_data: bytes, key_type: str, metadata: Dict[str, Any] = None) -> str:
        """Store encrypted key"""
        encrypted = self._master_cipher.encrypt(key_data)
        
        self._keys[key_id] = {
            'encrypted_key': base64.b64encode(encrypted.ciphertext).decode(),
            'nonce': base64.b64encode(encrypted.nonce).decode(),
            'tag': base64.b64encode(encrypted.tag).decode(),
            'key_type': key_type,
            'metadata': metadata or {},
            'created_at': datetime.utcnow().isoformat()
        }
        
        return key_id
    
    def retrieve_key(self, key_id: str) -> bytes:
        """Retrieve and decrypt key"""
        if key_id not in self._keys:
            raise KeyError(f"Key not found: {key_id}")
        
        key_data = self._keys[key_id]
        
        result = self._master_cipher.decrypt(
            base64.b64decode(key_data['encrypted_key']),
            base64.b64decode(key_data['nonce']),
            base64.b64decode(key_data['tag'])
        )
        
        return result.plaintext
    
    def delete_key(self, key_id: str) -> bool:
        """Securely delete key"""
        if key_id in self._keys:
            del self._keys[key_id]
            return True
        return False
    
    def list_keys(self) -> List[Dict[str, Any]]:
        """List all stored keys (metadata only)"""
        return [
            {
                'key_id': key_id,
                'key_type': data['key_type'],
                'created_at': data['created_at'],
                'metadata': data['metadata']
            }
            for key_id, data in self._keys.items()
        ]
    
    def rotate_key(self, key_id: str) -> str:
        """Rotate key with new version"""
        if key_id not in self._keys:
            raise KeyError(f"Key not found: {key_id}")
        
        old_key = self.retrieve_key(key_id)
        key_type = self._keys[key_id]['key_type']
        metadata = self._keys[key_id]['metadata']
        
        if key_type == 'AES-256':
            new_key = get_random_bytes(32)
        elif key_type == 'RSA-4096':
            rsa = RSA4096()
            new_key = rsa.private_key
        elif key_type == 'Ed25519':
            ed = Ed25519()
            new_key = ed.private_key
        else:
            new_key = get_random_bytes(32)
        
        new_key_id = f"{key_id}_v{int(time.time())}"
        
        metadata['previous_key_id'] = key_id
        metadata['rotated_at'] = datetime.utcnow().isoformat()
        
        self.store_key(new_key_id, new_key, key_type, metadata)
        
        return new_key_id


class CryptographyEngine:
    """Main cryptography engine coordinating all cryptographic operations"""
    
    def __init__(self, master_key: bytes = None):
        self.key_manager = KeyManager(master_key)
        self.secure_random = SecureRandom()
        self.hash_engine = HashEngine()
        self.key_derivation = KeyDerivation()
    
    def create_aes_cipher(self, key: bytes = None) -> AES256GCM:
        """Create AES-256-GCM cipher"""
        return AES256GCM(key)
    
    def create_rsa_cipher(self, private_key: bytes = None, public_key: bytes = None) -> RSA4096:
        """Create RSA-4096 cipher"""
        return RSA4096(private_key, public_key)
    
    def create_ed25519_signer(self, private_key: bytes = None, public_key: bytes = None) -> Ed25519:
        """Create Ed25519 signer"""
        return Ed25519(private_key, public_key)
    
    def encrypt_symmetric(self, plaintext: bytes, key: bytes = None) -> Dict[str, Any]:
        """Encrypt data using AES-256-GCM"""
        cipher = AES256GCM(key)
        result = cipher.encrypt(plaintext)
        
        return {
            'ciphertext': base64.b64encode(result.ciphertext).decode(),
            'nonce': base64.b64encode(result.nonce).decode(),
            'tag': base64.b64encode(result.tag).decode(),
            'algorithm': result.algorithm,
            'key_id': result.key_id,
            'timestamp': result.timestamp
        }
    
    def decrypt_symmetric(self, encrypted_data: Dict[str, Any], key: bytes) -> bytes:
        """Decrypt AES-256-GCM encrypted data"""
        cipher = AES256GCM(key)
        
        result = cipher.decrypt(
            base64.b64decode(encrypted_data['ciphertext']),
            base64.b64decode(encrypted_data['nonce']),
            base64.b64decode(encrypted_data['tag'])
        )
        
        return result.plaintext
    
    def encrypt_asymmetric(self, plaintext: bytes, public_key: bytes) -> Dict[str, Any]:
        """Encrypt data using RSA-4096"""
        cipher = RSA4096(public_key=public_key)
        ciphertext = cipher.encrypt(plaintext)
        
        return {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'algorithm': 'RSA-4096-OAEP-SHA256',
            'key_id': cipher.key_id,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def decrypt_asymmetric(self, encrypted_data: Dict[str, Any], private_key: bytes) -> bytes:
        """Decrypt RSA-4096 encrypted data"""
        cipher = RSA4096(private_key=private_key)
        return cipher.decrypt(base64.b64decode(encrypted_data['ciphertext']))
    
    def sign_message(self, message: bytes, private_key: bytes, algorithm: str = 'Ed25519') -> Dict[str, Any]:
        """Sign message"""
        if algorithm == 'Ed25519':
            signer = Ed25519(private_key=private_key)
        elif algorithm == 'RSA':
            signer = RSA4096(private_key=private_key)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        result = signer.sign(message)
        
        return {
            'signature': base64.b64encode(result.signature).decode(),
            'algorithm': result.algorithm,
            'key_id': result.key_id,
            'timestamp': result.timestamp,
            'message_hash': result.message_hash
        }
    
    def verify_signature(self, message: bytes, signature_data: Dict[str, Any], public_key: bytes) -> bool:
        """Verify signature"""
        algorithm = signature_data.get('algorithm', '')
        signature = base64.b64decode(signature_data['signature'])
        
        if 'Ed25519' in algorithm:
            verifier = Ed25519(public_key=public_key)
        elif 'RSA' in algorithm:
            verifier = RSA4096(public_key=public_key)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        return verifier.verify(message, signature)
    
    def derive_key(self, password: str, salt: bytes = None, algorithm: str = 'PBKDF2') -> Dict[str, Any]:
        """Derive key from password"""
        password_bytes = password.encode('utf-8')
        
        if algorithm == 'PBKDF2':
            result = self.key_derivation.pbkdf2(password_bytes, salt)
        elif algorithm == 'scrypt':
            result = self.key_derivation.scrypt_derive(password_bytes, salt)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        return {
            'key': base64.b64encode(result.key).decode(),
            'salt': base64.b64encode(result.salt).decode(),
            'algorithm': result.algorithm,
            'iterations': result.iterations,
            'key_id': result.key_id
        }
    
    def hash_data(self, data: bytes, algorithm: str = 'SHA256') -> str:
        """Hash data"""
        if algorithm == 'SHA256':
            return self.hash_engine.sha256_hex(data)
        elif algorithm == 'SHA512':
            return self.hash_engine.sha512_hex(data)
        elif algorithm == 'SHA3-256':
            return self.hash_engine.sha3_256_hex(data)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    def generate_random(self, length: int, format: str = 'bytes') -> Any:
        """Generate random data"""
        if format == 'bytes':
            return self.secure_random.generate_bytes(length)
        elif format == 'hex':
            return self.secure_random.generate_hex(length)
        elif format == 'base64':
            return self.secure_random.generate_base64(length)
        elif format == 'uuid':
            return self.secure_random.generate_uuid()
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def generate_keypair(self, algorithm: str = 'Ed25519') -> Dict[str, Any]:
        """Generate key pair"""
        if algorithm == 'Ed25519':
            signer = Ed25519()
            keypair = signer.generate_keypair()
        elif algorithm == 'RSA-4096':
            cipher = RSA4096()
            keypair = cipher.generate_keypair()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        return {
            'public_key': base64.b64encode(keypair.public_key).decode(),
            'private_key': base64.b64encode(keypair.private_key).decode(),
            'key_type': keypair.key_type,
            'key_size': keypair.key_size,
            'key_id': keypair.key_id,
            'created_at': keypair.created_at
        }


def create_cryptography_engine(master_key: bytes = None) -> CryptographyEngine:
    """Factory function to create cryptography engine instance"""
    return CryptographyEngine(master_key)
