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
    def __init__(self, root_key: bytes, auto_rekey_callback: Optional[Callable] = None, 
                 rekey_interval_messages: int = 100, rekey_interval_seconds: int = 600,
                 is_initiator: bool = True):
        self.root_key = root_key
        self.send_chain_key = None
        self.recv_chain_key = None
        self.send_message_count = 0
        self.recv_message_count = 0
        self.auto_rekey_callback = auto_rekey_callback
        self.rekey_interval_messages = rekey_interval_messages
        self.rekey_interval_seconds = rekey_interval_seconds
        self._last_rekey_time = time.time()
        self.is_initiator = is_initiator
        self._init_chains()

    def _init_chains(self):
        key_a = HKDF(algorithm=hashes.SHA3_256(), length=32, 
                     salt=b'hyperion-send-chain-v1', info=b'double-ratchet-send', 
                     backend=default_backend()).derive(self.root_key)
        key_b = HKDF(algorithm=hashes.SHA3_256(), length=32, 
                     salt=b'hyperion-recv-chain-v1', info=b'double-ratchet-recv', 
                     backend=default_backend()).derive(self.root_key)
        
        if self.is_initiator:
            self.send_chain_key = key_a
            self.recv_chain_key = key_b
        else:
            self.send_chain_key = key_b
            self.recv_chain_key = key_a

    def _ratchet_chain(self, chain_key: bytes) -> bytes:
        return hashlib.sha3_256(chain_key + b'chain_step').digest()

    def _message_key(self, chain_key: bytes, counter: int) -> bytes:
        return hashlib.sha3_256(chain_key + counter.to_bytes(8, 'big')).digest()

    def _check_rekey(self):
        now = time.time()
        need = self.send_message_count >= self.rekey_interval_messages or self.recv_message_count >= self.rekey_interval_messages or now - self._last_rekey_time >= self.rekey_interval_seconds
        if need and self.auto_rekey_callback:
            self.auto_rekey_callback()
            self._last_rekey_time = now
            self.send_message_count = 0
            self.recv_message_count = 0

    def encrypt(self, plaintext: str) -> dict:
        current_counter = self.send_message_count
        mk = self._message_key(self.send_chain_key, current_counter)
        self.send_chain