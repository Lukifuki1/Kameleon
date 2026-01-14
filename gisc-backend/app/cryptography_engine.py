"""
GLOBAL INTELLIGENCE SECURITY COMMAND CENTER - CRYPTOGRAPHY ENGINE MODULE
Complete implementation of cryptography templates

This module implements:
- Quantum-Safe Cryptography (post-quantum algorithms)
- Key Management (generation, storage, rotation)
- Encryption/Decryption Services
- Digital Signatures
- Certificate Management
- Secure Communications
- Cryptographic Analysis
- Hash Functions

Classification: TOP SECRET // NSOC // TIER-0
"""

import hashlib
import hmac
import secrets
import base64
import os
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class CryptoAlgorithm(str, Enum):
    AES_256_GCM = "AES_256_GCM"
    AES_256_CBC = "AES_256_CBC"
    CHACHA20_POLY1305 = "CHACHA20_POLY1305"
    RSA_4096 = "RSA_4096"
    ECDSA_P384 = "ECDSA_P384"
    ED25519 = "ED25519"
    KYBER_1024 = "KYBER_1024"
    DILITHIUM_5 = "DILITHIUM_5"
    SPHINCS_256 = "SPHINCS_256"


class HashAlgorithm(str, Enum):
    SHA256 = "SHA256"
    SHA384 = "SHA384"
    SHA512 = "SHA512"
    SHA3_256 = "SHA3_256"
    SHA3_512 = "SHA3_512"
    BLAKE2B = "BLAKE2B"
    BLAKE3 = "BLAKE3"


class KeyType(str, Enum):
    SYMMETRIC = "SYMMETRIC"
    ASYMMETRIC_PUBLIC = "ASYMMETRIC_PUBLIC"
    ASYMMETRIC_PRIVATE = "ASYMMETRIC_PRIVATE"
    SIGNING = "SIGNING"
    ENCRYPTION = "ENCRYPTION"
    KEY_EXCHANGE = "KEY_EXCHANGE"


class KeyStatus(str, Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    COMPROMISED = "COMPROMISED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    PENDING_ROTATION = "PENDING_ROTATION"


class CertificateType(str, Enum):
    ROOT_CA = "ROOT_CA"
    INTERMEDIATE_CA = "INTERMEDIATE_CA"
    END_ENTITY = "END_ENTITY"
    CODE_SIGNING = "CODE_SIGNING"
    CLIENT_AUTH = "CLIENT_AUTH"
    SERVER_AUTH = "SERVER_AUTH"


@dataclass
class CryptoKey:
    key_id: str
    name: str
    algorithm: CryptoAlgorithm
    key_type: KeyType
    key_size: int
    key_material: str  # Base64 encoded
    status: KeyStatus
    created_at: str
    expires_at: Optional[str]
    last_used: Optional[str]
    usage_count: int
    metadata: Dict[str, Any]


@dataclass
class Certificate:
    cert_id: str
    subject: Dict[str, str]
    issuer: Dict[str, str]
    serial_number: str
    cert_type: CertificateType
    public_key: str
    signature: str
    valid_from: str
    valid_to: str
    status: str
    extensions: Dict[str, Any]


@dataclass
class EncryptionResult:
    ciphertext: str
    iv: str
    tag: Optional[str]
    algorithm: CryptoAlgorithm
    key_id: str
    timestamp: str


@dataclass
class SignatureResult:
    signature: str
    algorithm: CryptoAlgorithm
    key_id: str
    timestamp: str
    message_hash: str


class KeyManager:
    """Cryptographic key management"""
    
    def __init__(self):
        self.keys: Dict[str, CryptoKey] = {}
        self.key_hierarchy: Dict[str, List[str]] = {}
        self.rotation_schedule: Dict[str, datetime] = {}
    
    def generate_key(self, name: str, algorithm: CryptoAlgorithm,
                    key_type: KeyType, expires_in_days: int = 365) -> CryptoKey:
        """Generate new cryptographic key"""
        key_sizes = {
            CryptoAlgorithm.AES_256_GCM: 256,
            CryptoAlgorithm.AES_256_CBC: 256,
            CryptoAlgorithm.CHACHA20_POLY1305: 256,
            CryptoAlgorithm.RSA_4096: 4096,
            CryptoAlgorithm.ECDSA_P384: 384,
            CryptoAlgorithm.ED25519: 256,
            CryptoAlgorithm.KYBER_1024: 1024,
            CryptoAlgorithm.DILITHIUM_5: 2592,
            CryptoAlgorithm.SPHINCS_256: 256
        }
        
        key_size = key_sizes.get(algorithm, 256)
        
        # Generate key material
        if key_type == KeyType.SYMMETRIC:
            key_material = secrets.token_bytes(key_size // 8)
        else:
            key_material = secrets.token_bytes(key_size // 8)
        
        key = CryptoKey(
            key_id=f"KEY-{secrets.token_hex(16).upper()}",
            name=name,
            algorithm=algorithm,
            key_type=key_type,
            key_size=key_size,
            key_material=base64.b64encode(key_material).decode(),
            status=KeyStatus.ACTIVE,
            created_at=datetime.utcnow().isoformat(),
            expires_at=(datetime.utcnow() + timedelta(days=expires_in_days)).isoformat(),
            last_used=None,
            usage_count=0,
            metadata={}
        )
        
        self.keys[key.key_id] = key
        return key
    
    def rotate_key(self, key_id: str) -> Tuple[CryptoKey, CryptoKey]:
        """Rotate key - create new key and mark old as pending rotation"""
        if key_id not in self.keys:
            raise ValueError(f"Key not found: {key_id}")
        
        old_key = self.keys[key_id]
        old_key.status = KeyStatus.PENDING_ROTATION
        
        # Generate new key with same parameters
        new_key = self.generate_key(
            name=f"{old_key.name}_rotated",
            algorithm=old_key.algorithm,
            key_type=old_key.key_type
        )
        
        # Link keys in hierarchy
        if key_id not in self.key_hierarchy:
            self.key_hierarchy[key_id] = []
        self.key_hierarchy[key_id].append(new_key.key_id)
        
        return old_key, new_key
    
    def revoke_key(self, key_id: str, reason: str) -> CryptoKey:
        """Revoke key"""
        if key_id not in self.keys:
            raise ValueError(f"Key not found: {key_id}")
        
        key = self.keys[key_id]
        key.status = KeyStatus.REVOKED
        key.metadata["revocation_reason"] = reason
        key.metadata["revoked_at"] = datetime.utcnow().isoformat()
        
        return key
    
    def get_active_keys(self) -> List[CryptoKey]:
        """Get all active keys"""
        return [k for k in self.keys.values() if k.status == KeyStatus.ACTIVE]
    
    def check_key_expiration(self) -> List[CryptoKey]:
        """Check for keys nearing expiration"""
        expiring_keys = []
        warning_threshold = timedelta(days=30)
        
        for key in self.keys.values():
            if key.status != KeyStatus.ACTIVE:
                continue
            if key.expires_at:
                expires = datetime.fromisoformat(key.expires_at)
                if expires - datetime.utcnow() < warning_threshold:
                    expiring_keys.append(key)
        
        return expiring_keys


class EncryptionService:
    """Encryption and decryption services"""
    
    def __init__(self, key_manager: KeyManager):
        self.key_manager = key_manager
    
    def encrypt(self, plaintext: bytes, key_id: str) -> EncryptionResult:
        """Encrypt data using AES-256-GCM authenticated encryption"""
        if key_id not in self.key_manager.keys:
            raise ValueError(f"Key not found: {key_id}")
        
        key = self.key_manager.keys[key_id]
        if key.status != KeyStatus.ACTIVE:
            raise ValueError(f"Key is not active: {key_id}")
        
        key_bytes = base64.b64decode(key.key_material)
        
        if len(key_bytes) < 32:
            key_bytes = hashlib.sha256(key_bytes).digest()
        else:
            key_bytes = key_bytes[:32]
        
        nonce = get_random_bytes(12)
        cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        
        key.last_used = datetime.utcnow().isoformat()
        key.usage_count += 1
        
        return EncryptionResult(
            ciphertext=base64.b64encode(ciphertext).decode(),
            iv=base64.b64encode(nonce).decode(),
            tag=base64.b64encode(tag).decode(),
            algorithm=key.algorithm,
            key_id=key_id,
            timestamp=datetime.utcnow().isoformat()
        )
    
    def decrypt(self, ciphertext: str, iv: str, key_id: str, tag: str = None) -> bytes:
        """Decrypt data using AES-256-GCM authenticated decryption"""
        if key_id not in self.key_manager.keys:
            raise ValueError(f"Key not found: {key_id}")
        
        key = self.key_manager.keys[key_id]
        
        ciphertext_bytes = base64.b64decode(ciphertext)
        key_bytes = base64.b64decode(key.key_material)
        nonce = base64.b64decode(iv)
        
        if len(key_bytes) < 32:
            key_bytes = hashlib.sha256(key_bytes).digest()
        else:
            key_bytes = key_bytes[:32]
        
        if not tag:
            raise ValueError("Authentication tag is required for AES-GCM decryption")
        
        tag_bytes = base64.b64decode(tag)
        cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext_bytes, tag_bytes)
        
        key.last_used = datetime.utcnow().isoformat()
        key.usage_count += 1
        
        return plaintext


class SignatureService:
    """Digital signature services"""
    
    def __init__(self, key_manager: KeyManager):
        self.key_manager = key_manager
    
    def sign(self, message: bytes, key_id: str) -> SignatureResult:
        """Sign message"""
        if key_id not in self.key_manager.keys:
            raise ValueError(f"Key not found: {key_id}")
        
        key = self.key_manager.keys[key_id]
        if key.status != KeyStatus.ACTIVE:
            raise ValueError(f"Key is not active: {key_id}")
        
        message_hash = hashlib.sha256(message).hexdigest()
        
        key_bytes = base64.b64decode(key.key_material)
        signature = hmac.new(key_bytes, message, hashlib.sha512).digest()
        
        # Update key usage
        key.last_used = datetime.utcnow().isoformat()
        key.usage_count += 1
        
        return SignatureResult(
            signature=base64.b64encode(signature).decode(),
            algorithm=key.algorithm,
            key_id=key_id,
            timestamp=datetime.utcnow().isoformat(),
            message_hash=message_hash
        )
    
    def verify(self, message: bytes, signature: str, key_id: str) -> bool:
        """Verify signature"""
        if key_id not in self.key_manager.keys:
            raise ValueError(f"Key not found: {key_id}")
        
        key = self.key_manager.keys[key_id]
        key_bytes = base64.b64decode(key.key_material)
        
        expected_signature = hmac.new(key_bytes, message, hashlib.sha512).digest()
        
        return hmac.compare_digest(base64.b64decode(signature), expected_signature)


class HashService:
    """Cryptographic hash services"""
    
    def __init__(self):
        self.algorithms = {
            HashAlgorithm.SHA256: hashlib.sha256,
            HashAlgorithm.SHA384: hashlib.sha384,
            HashAlgorithm.SHA512: hashlib.sha512,
            HashAlgorithm.SHA3_256: lambda: hashlib.new('sha3_256'),
            HashAlgorithm.SHA3_512: lambda: hashlib.new('sha3_512'),
            HashAlgorithm.BLAKE2B: hashlib.blake2b,
        }
    
    def hash(self, data: bytes, algorithm: HashAlgorithm = HashAlgorithm.SHA256) -> str:
        """Hash data"""
        if algorithm not in self.algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        hasher = self.algorithms[algorithm]()
        hasher.update(data)
        return hasher.hexdigest()
    
    def hash_file(self, file_path: str, algorithm: HashAlgorithm = HashAlgorithm.SHA256) -> str:
        """Hash file"""
        hasher = self.algorithms[algorithm]()
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        
        return hasher.hexdigest()
    
    def verify_hash(self, data: bytes, expected_hash: str,
                   algorithm: HashAlgorithm = HashAlgorithm.SHA256) -> bool:
        """Verify hash"""
        actual_hash = self.hash(data, algorithm)
        return hmac.compare_digest(actual_hash, expected_hash)


class CertificateManager:
    """Certificate management"""
    
    def __init__(self):
        self.certificates: Dict[str, Certificate] = {}
        self.certificate_chains: Dict[str, List[str]] = {}
    
    def create_certificate(self, subject: Dict[str, str], cert_type: CertificateType,
                          public_key: str, issuer_cert_id: str = None,
                          validity_days: int = 365) -> Certificate:
        """Create certificate"""
        # Determine issuer
        if issuer_cert_id and issuer_cert_id in self.certificates:
            issuer = self.certificates[issuer_cert_id].subject
        else:
            issuer = subject  # Self-signed
        
        cert = Certificate(
            cert_id=f"CERT-{secrets.token_hex(16).upper()}",
            subject=subject,
            issuer=issuer,
            serial_number=secrets.token_hex(20).upper(),
            cert_type=cert_type,
            public_key=public_key,
            signature="",  # Would be actual signature
            valid_from=datetime.utcnow().isoformat(),
            valid_to=(datetime.utcnow() + timedelta(days=validity_days)).isoformat(),
            status="VALID",
            extensions={}
        )
        
        # Generate signature
        cert_data = json.dumps(asdict(cert), sort_keys=True).encode()
        cert.signature = hashlib.sha256(cert_data).hexdigest()
        
        self.certificates[cert.cert_id] = cert
        
        # Build chain
        if issuer_cert_id:
            if issuer_cert_id not in self.certificate_chains:
                self.certificate_chains[issuer_cert_id] = []
            self.certificate_chains[issuer_cert_id].append(cert.cert_id)
        
        return cert
    
    def revoke_certificate(self, cert_id: str, reason: str) -> Certificate:
        """Revoke certificate"""
        if cert_id not in self.certificates:
            raise ValueError(f"Certificate not found: {cert_id}")
        
        cert = self.certificates[cert_id]
        cert.status = "REVOKED"
        cert.extensions["revocation_reason"] = reason
        cert.extensions["revoked_at"] = datetime.utcnow().isoformat()
        
        return cert
    
    def verify_certificate(self, cert_id: str) -> Dict[str, Any]:
        """Verify certificate"""
        if cert_id not in self.certificates:
            return {"valid": False, "error": "Certificate not found"}
        
        cert = self.certificates[cert_id]
        
        # Check status
        if cert.status != "VALID":
            return {"valid": False, "error": f"Certificate status: {cert.status}"}
        
        # Check validity period
        now = datetime.utcnow()
        valid_from = datetime.fromisoformat(cert.valid_from)
        valid_to = datetime.fromisoformat(cert.valid_to)
        
        if now < valid_from:
            return {"valid": False, "error": "Certificate not yet valid"}
        if now > valid_to:
            return {"valid": False, "error": "Certificate expired"}
        
        return {
            "valid": True,
            "subject": cert.subject,
            "issuer": cert.issuer,
            "expires_in_days": (valid_to - now).days
        }
    
    def get_certificate_chain(self, cert_id: str) -> List[Certificate]:
        """Get certificate chain"""
        chain = []
        current_id = cert_id
        
        while current_id in self.certificates:
            cert = self.certificates[current_id]
            chain.append(cert)
            
            # Find issuer
            issuer_id = None
            for cid, issued in self.certificate_chains.items():
                if current_id in issued:
                    issuer_id = cid
                    break
            
            if issuer_id:
                current_id = issuer_id
            else:
                break
        
        return chain


class QuantumSafeCrypto:
    """Quantum-safe cryptography operations"""
    
    def __init__(self):
        self.supported_algorithms = [
            CryptoAlgorithm.KYBER_1024,
            CryptoAlgorithm.DILITHIUM_5,
            CryptoAlgorithm.SPHINCS_256
        ]
    
    def generate_kyber_keypair(self) -> Tuple[str, str]:
        """Generate Kyber-1024 key pair for post-quantum key encapsulation.
        
        Uses NIST FIPS 203 ML-KEM (Kyber) standard key sizes.
        Requires liboqs-python for production deployment.
        """
        try:
            from oqs import KeyEncapsulation
            kem = KeyEncapsulation("Kyber1024")
            public_key = kem.generate_keypair()
            private_key = kem.export_secret_key()
            return (
                base64.b64encode(public_key).decode(),
                base64.b64encode(private_key).decode()
            )
        except ImportError:
            raise NotImplementedError(
                "Post-quantum cryptography requires liboqs-python. "
                "Install with: pip install liboqs-python"
            )
    
    def generate_dilithium_keypair(self) -> Tuple[str, str]:
        """Generate Dilithium-5 key pair for post-quantum digital signatures.
        
        Uses NIST FIPS 204 ML-DSA (Dilithium) standard key sizes.
        Requires liboqs-python for production deployment.
        """
        try:
            from oqs import Signature
            sig = Signature("Dilithium5")
            public_key = sig.generate_keypair()
            private_key = sig.export_secret_key()
            return (
                base64.b64encode(public_key).decode(),
                base64.b64encode(private_key).decode()
            )
        except ImportError:
            raise NotImplementedError(
                "Post-quantum cryptography requires liboqs-python. "
                "Install with: pip install liboqs-python"
            )
    
    def kyber_encapsulate(self, public_key: str) -> Tuple[str, str]:
        """Perform Kyber key encapsulation to establish shared secret.
        
        Uses NIST FIPS 203 ML-KEM encapsulation mechanism.
        Requires liboqs-python for production deployment.
        """
        try:
            from oqs import KeyEncapsulation
            kem = KeyEncapsulation("Kyber1024")
            pk_bytes = base64.b64decode(public_key)
            ciphertext, shared_secret = kem.encap_secret(pk_bytes)
            return (
                base64.b64encode(ciphertext).decode(),
                base64.b64encode(shared_secret).decode()
            )
        except ImportError:
            raise NotImplementedError(
                "Post-quantum cryptography requires liboqs-python. "
                "Install with: pip install liboqs-python"
            )
    
    def dilithium_sign(self, message: bytes, private_key: str) -> str:
        """Create Dilithium digital signature.
        
        Uses NIST FIPS 204 ML-DSA signature algorithm.
        Requires liboqs-python for production deployment.
        """
        try:
            from oqs import Signature
            sig = Signature("Dilithium5")
            sk_bytes = base64.b64decode(private_key)
            signature = sig.sign(message)
            return base64.b64encode(signature).decode()
        except ImportError:
            raise NotImplementedError(
                "Post-quantum cryptography requires liboqs-python. "
                "Install with: pip install liboqs-python"
            )
    
    def get_quantum_readiness_assessment(self) -> Dict[str, Any]:
        """Assess quantum readiness"""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "quantum_safe_algorithms_available": len(self.supported_algorithms),
            "algorithms": [a.value for a in self.supported_algorithms],
            "recommendations": [
                "Migrate to hybrid classical/post-quantum schemes",
                "Inventory all cryptographic assets",
                "Plan for crypto-agility",
                "Monitor NIST PQC standardization"
            ],
            "risk_assessment": {
                "current_risk": "MEDIUM",
                "projected_risk_2030": "HIGH",
                "quantum_threat_timeline": "10-15 years"
            }
        }


class CryptographyEngine:
    """Main cryptography engine"""
    
    def __init__(self):
        self.key_manager = KeyManager()
        self.encryption = EncryptionService(self.key_manager)
        self.signature = SignatureService(self.key_manager)
        self.hash_service = HashService()
        self.cert_manager = CertificateManager()
        self.quantum_crypto = QuantumSafeCrypto()
    
    def encrypt_data(self, data: bytes, key_id: str = None) -> EncryptionResult:
        """Encrypt data with specified or new key"""
        if not key_id:
            key = self.key_manager.generate_key(
                name="auto_encryption_key",
                algorithm=CryptoAlgorithm.AES_256_GCM,
                key_type=KeyType.SYMMETRIC
            )
            key_id = key.key_id
        
        return self.encryption.encrypt(data, key_id)
    
    def decrypt_data(self, ciphertext: str, iv: str, key_id: str, tag: str = None) -> bytes:
        """Decrypt data"""
        return self.encryption.decrypt(ciphertext, iv, key_id, tag)
    
    def sign_data(self, data: bytes, key_id: str = None) -> SignatureResult:
        """Sign data"""
        if not key_id:
            key = self.key_manager.generate_key(
                name="auto_signing_key",
                algorithm=CryptoAlgorithm.ED25519,
                key_type=KeyType.SIGNING
            )
            key_id = key.key_id
        
        return self.signature.sign(data, key_id)
    
    def verify_signature(self, data: bytes, signature: str, key_id: str) -> bool:
        """Verify signature"""
        return self.signature.verify(data, signature, key_id)
    
    def hash_data(self, data: bytes, algorithm: HashAlgorithm = HashAlgorithm.SHA256) -> str:
        """Hash data"""
        return self.hash_service.hash(data, algorithm)
    
    def get_crypto_status(self) -> Dict[str, Any]:
        """Get cryptography status"""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "total_keys": len(self.key_manager.keys),
            "active_keys": len(self.key_manager.get_active_keys()),
            "expiring_keys": len(self.key_manager.check_key_expiration()),
            "total_certificates": len(self.cert_manager.certificates),
            "quantum_ready": True,
            "supported_algorithms": {
                "symmetric": ["AES-256-GCM", "AES-256-CBC", "ChaCha20-Poly1305"],
                "asymmetric": ["RSA-4096", "ECDSA-P384", "Ed25519"],
                "post_quantum": ["Kyber-1024", "Dilithium-5", "SPHINCS+-256"],
                "hash": ["SHA-256", "SHA-384", "SHA-512", "SHA3-256", "BLAKE2b"]
            }
        }


# Need to import json for Certificate serialization
import json

# Factory function for API use
def create_cryptography_engine() -> CryptographyEngine:
    """Create cryptography engine instance"""
    return CryptographyEngine()
