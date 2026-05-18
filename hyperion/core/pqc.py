import hashlib
import base64
import secrets
from typing import Tuple, Optional

try:
    import oqs
    PQC_AVAILABLE = True
except ImportError:
    PQC_AVAILABLE = False

class PQCKyber:
    def __init__(self, kem_alg: str = "Kyber512"):
        if not PQC_AVAILABLE:
            raise ImportError("liboqs-python required")
        self.kem_alg = kem_alg
        self._kem = None
        self.public_key = None
        self._init_kem()

    def _init_kem(self):
        self._kem = oqs.KeyEncapsulation(self.kem_alg)
        self.public_key = self._kem.generate_keypair()

    def get_public_key(self) -> str:
        return base64.b64encode(self.public_key).decode()

    def encapsulate(self, peer_public_key_b64: str) -> Tuple[bytes, str]:
        peer_public_key = base64.b64decode(peer_public_key_b64)
        ciphertext, shared_secret = self._kem.encap_secret(peer_public_key)
        return shared_secret, base64.b64encode(ciphertext).decode()

    def decapsulate(self, ciphertext_b64: str) -> bytes:
        ciphertext = base64.b64decode(ciphertext_b64)
        shared_secret = self._kem.decap_secret(ciphertext)
        return shared_secret

    def cleanup(self):
        if self._kem:
            self._kem.cleanup()
            self._kem = None

    @staticmethod
    def derive_root_key(shared_secret: bytes) -> bytes:
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        return HKDF(algorithm=hashes.SHA3_256(), length=32, salt=b'hyperion-pqc-root-v1', info=b'kyber512-double-ratchet', backend=default_backend()).derive(shared_secret)

class PQCDilithium:
    def __init__(self, sig_alg: str = "Dilithium5"):
        if not PQC_AVAILABLE:
            raise ImportError("liboqs-python required")
        self.sig_alg = sig_alg
        self._signer = None
        self.public_key = None
        self.secret_key = None
        self._init_keys()

    def _init_keys(self):
        self._signer = oqs.Signature(self.sig_alg)
        self.public_key = self._signer.generate_keypair()
        self.secret_key = self._signer.export_secret_key()

    def sign(self, message: bytes) -> str:
        signature = self._signer.sign(message)
        return base64.b64encode(signature).decode()

    def verify(self, signature_b64: str, message: bytes, public_key_b64: str) -> bool:
        try:
            signature = base64.b64decode(signature_b64)
            public_key = base64.b64decode(public_key_b64)
            verifier = oqs.Signature(self.sig_alg)
            result = verifier.verify(message, signature, public_key)
            verifier.cleanup()
            return result
        except:
            return False

    def get_public_key(self) -> str:
        return base64.b64encode(self.public_key).decode()

    def get_secret_key(self) -> str:
        return base64.b64encode(self.secret_key).decode()

    def cleanup(self):
        if self._signer:
            self._signer.cleanup()
            self._signer = None

class MultiKDF:
    @staticmethod
    def derive(password: str, salt: bytes, iterations: int = 100000) -> bytes:
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        try:
            import argon2
            HAS_ARGON2 = True
        except ImportError:
            HAS_ARGON2 = False
        if HAS_ARGON2:
            ph = argon2.PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32)
            argon_hash = ph.hash(password).encode()[:32]
        else:
            argon_hash = hashlib.sha3_256(password.encode() + salt + b'argon2_fallback').digest()
        scrypt_kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
        scrypt_hash = scrypt_kdf.derive(password.encode())
        pbkdf2 = PBKDF2HMAC(algorithm=hashes.SHA3_512(), length=32, salt=salt, iterations=iterations, backend=default_backend())
        pbkdf2_hash = pbkdf2.derive(password.encode())
        combined = bytes(a ^ b ^ c for a, b, c in zip(argon_hash, scrypt_hash, pbkdf2_hash))
        return hashlib.sha3_512(combined + salt).digest()[:32]