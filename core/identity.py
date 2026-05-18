import os
import json
import base64
import secrets
import hashlib
from pathlib import Path
from typing import Optional, Dict, Callable
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

class SecureIdentity:
    def __init__(self, storage_path: str = "hyperion_identity.json", password_callback: Optional[Callable] = None):
        self.storage_path = Path(storage_path)
        self.password_callback = password_callback
        self._key: Optional[ed25519.Ed25519PrivateKey] = None
        self._load_or_generate()

    def _default_ask_password(self, prompt: str, title: str) -> Optional[str]:
        import getpass
        return getpass.getpass(f"{prompt}: ")

    def _ask_password(self, prompt: str, title: str) -> Optional[str]:
        if self.password_callback:
            return self.password_callback(prompt, title)
        return self._default_ask_password(prompt, title)

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
        return kdf.derive(password.encode())

    def _encrypt_private_key(self, private_bytes: bytes, password: str) -> Dict[str, str]:
        salt = secrets.token_bytes(16)
        key = self._derive_key(password, salt)
        nonce = secrets.token_bytes(12)
        cipher = AESGCM(key)
        ciphertext = cipher.encrypt(nonce, private_bytes, None)
        return {'salt': base64.b64encode(salt).decode(), 'nonce': base64.b64encode(nonce).decode(), 'ciphertext': base64.b64encode(ciphertext).decode()}

    def _decrypt_private_key(self, enc_data: Dict[str, str], password: str) -> bytes:
        salt = base64.b64decode(enc_data['salt'])
        nonce = base64.b64decode(enc_data['nonce'])
        ciphertext = base64.b64decode(enc_data['ciphertext'])
        key = self._derive_key(password, salt)
        cipher = AESGCM(key)
        return cipher.decrypt(nonce, ciphertext, None)

    def _load_or_generate(self):
        if self.storage_path.exists():
            try:
                with open(self.storage_path, 'r') as f:
                    data = json.load(f)
                if 'encrypted' in data:
                    for attempt in range(3):
                        password = self._ask_password(f"Enter identity password (attempt {attempt+1}/3)", "Unlock Identity")
                        if password is None:
                            raise ValueError("Password cancelled")
                        try:
                            private_bytes = self._decrypt_private_key(data['encrypted'], password)
                            self._key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
                            return
                        except Exception:
                            if attempt == 2:
                                raise ValueError("Wrong password after 3 attempts")
                    return
            except Exception:
                pass
        self._key = ed25519.Ed25519PrivateKey.generate()
        private_bytes = self._key.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
        password = self._ask_password("Set password for identity storage", "Create Identity")
        if password is None:
            raise ValueError("Password required")
        confirm = self._ask_password("Confirm password", "Confirm Password")
        if confirm is None or password != confirm:
            raise ValueError("Passwords do not match")
        encrypted = self._encrypt_private_key(private_bytes, password)
        with open(self.storage_path, 'w') as f:
            json.dump({'encrypted': encrypted, 'version': 2}, f)

    def get_public_key(self) -> bytes:
        return self._key.public_key().public_bytes_raw()

    def get_fingerprint(self) -> str:
        return hashlib.sha3_256(self.get_public_key()).hexdigest()[:16]

    def sign(self, data: bytes) -> bytes:
        return self._key.sign(data)

    @staticmethod
    def verify(signature: bytes, data: bytes, public_key: bytes) -> bool:
        try:
            pub_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
            pub_key.verify(signature, data)
            return True
        except:
            return False

    def wipe_memory(self):
        self._key = None
