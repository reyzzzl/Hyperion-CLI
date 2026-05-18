import hashlib
import base64
import secrets
import time
from typing import Optional, Callable
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class DoubleRatchet:
    def __init__(self, root_key: bytes, auto_rekey_callback: Optional[Callable] = None, rekey_interval_messages: int = 100, rekey_interval_seconds: int = 600):
        self.root_key = root_key
        self.send_chain_key = None
        self.recv_chain_key = None
        self.send_message_count = 0
        self.recv_message_count = 0
        self.auto_rekey_callback = auto_rekey_callback
        self.rekey_interval_messages = rekey_interval_messages
        self.rekey_interval_seconds = rekey_interval_seconds
        self._last_rekey_time = time.time()
        self._init_chains()

    def _init_chains(self):
        self.send_chain_key = HKDF(algorithm=hashes.SHA3_256(), length=32, salt=b'hyperion-send-chain-v1', info=b'double-ratchet-send', backend=default_backend()).derive(self.root_key)
        self.recv_chain_key = HKDF(algorithm=hashes.SHA3_256(), length=32, salt=b'hyperion-recv-chain-v1', info=b'double-ratchet-recv', backend=default_backend()).derive(self.root_key)

    def _ratchet_chain(self, chain_key: bytes) -> bytes:
        return hashlib.sha3_256(chain_key + b'chain_step').digest()

    def _message_key(self, chain_key: bytes, counter: int) -> bytes:
        return hashlib.sha3_256(chain_key + counter.to_bytes(8, 'big')).digest()

    def _check_rekey(self):
        now = time.time()
        need_rekey = (self.send_message_count >= self.rekey_interval_messages or self.recv_message_count >= self.rekey_interval_messages or now - self._last_rekey_time >= self.rekey_interval_seconds)
        if need_rekey and self.auto_rekey_callback:
            self.auto_rekey_callback()
            self._last_rekey_time = now
            self.send_message_count = 0
            self.recv_message_count = 0

    def encrypt(self, plaintext: str) -> dict:
        self._check_rekey()
        message_key = self._message_key(self.send_chain_key, self.send_message_count)
        self.send_chain_key = self._ratchet_chain(self.send_chain_key)
        self.send_message_count += 1
        iv = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES256(message_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        return {'iv': base64.b64encode(iv).decode(), 'tag': base64.b64encode(encryptor.tag).decode(), 'ct': base64.b64encode(ciphertext).decode(), 'counter': self.send_message_count - 1}

    def decrypt(self, data: dict) -> str:
        iv = base64.b64decode(data['iv'])
        tag = base64.b64decode(data['tag'])
        ciphertext = base64.b64decode(data['ct'])
        received_counter = data['counter']
        if received_counter < self.recv_message_count:
            raise ValueError("Replay attack detected")
        while received_counter > self.recv_message_count:
            self._message_key(self.recv_chain_key, self.recv_message_count)
            self.recv_chain_key = self._ratchet_chain(self.recv_chain_key)
            self.recv_message_count += 1
        message_key = self._message_key(self.recv_chain_key, received_counter)
        self.recv_chain_key = self._ratchet_chain(self.recv_chain_key)
        self.recv_message_count += 1
        cipher = Cipher(algorithms.AES256(message_key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode()

    def rekey(self):
        self.root_key = hashlib.sha3_256(self.root_key + b'rekey').digest()
        self.send_message_count = 0
        self.recv_message_count = 0
        self._init_chains()
        return True

    def get_stats(self) -> dict:
        return {'send_count': self.send_message_count, 'recv_count': self.recv_message_count, 'last_rekey': self._last_rekey_time}

    def wipe_memory(self):
        self.root_key = secrets.token_bytes(32)
        self.send_chain_key = secrets.token_bytes(32)
        self.recv_chain_key = secrets.token_bytes(32)
