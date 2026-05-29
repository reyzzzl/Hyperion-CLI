import sqlite3
import threading
from dataclasses import dataclass, field
from typing import Dict, Optional, List
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
import base64
import secrets
import os

@dataclass
class ChatSession:
    peer_address: str
    peer_fingerprint: str
    shared_secret: bytes
    ratchet: 'DoubleRatchet'
    last_active: datetime = field(default_factory=datetime.now)
    message_queue: List[dict] = field(default_factory=list)
    send_counter: int = 0
    recv_counter: int = 0

class SessionManager:
    def __init__(self, db_path: str = "hyperion_sessions.db", encryption_password: str = None):
        self.sessions: Dict[str, ChatSession] = {}
        self.lock = threading.Lock()
        self.db_path = db_path
        self.encryption_password = encryption_password
        self._init_db()

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
        return kdf.derive(password.encode())

    def _encrypt_secret(self, secret: bytes) -> str:
        if not self.encryption_password:
            return base64.b64encode(secret).decode()
        salt = secrets.token_bytes(16)
        key = self._derive_key(self.encryption_password, salt)
        nonce = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES256(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(secret) + encryptor.finalize()
        combined = salt + nonce + encryptor.tag + ciphertext
        return base64.b64encode(combined).decode()

    def _decrypt_secret(self, enc_secret: str) -> bytes:
        if not self.encryption_password:
            return base64.b64decode(enc_secret)
        raw = base64.b64decode(enc_secret)
        salt = raw[:16]
        nonce = raw[16:28]
        tag = raw[28:44]
        ciphertext = raw[44:]
        key = self._derive_key(self.encryption_password, salt)
        cipher = Cipher(algorithms.AES256(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute('''CREATE TABLE IF NOT EXISTS sessions (
            peer_address TEXT PRIMARY KEY,
            peer_fingerprint TEXT,
            shared_secret TEXT,
            last_active TIMESTAMP,
            send_counter INTEGER DEFAULT 0,
            recv_counter INTEGER DEFAULT 0
        )''')
        conn.execute('CREATE TABLE IF NOT EXISTS message_queue (id INTEGER PRIMARY KEY AUTOINCREMENT, peer_address TEXT, message TEXT, timestamp TIMESTAMP, delivered BOOLEAN DEFAULT 0)')
        conn.commit()
        conn.close()

    def set_encryption_password(self, password: str):
        self.encryption_password = password

    def add_session(self, session: ChatSession):
        with self.lock:
            self.sessions[session.peer_address] = session
            self._save_session(session)

    def get_session(self, address: str) -> Optional[ChatSession]:
        with self.lock:
            return self.sessions.get(address)

    def remove_session(self, address: str):
        with self.lock:
            if address in self.sessions:
                del self.sessions[address]

    def list_sessions(self) -> List[dict]:
        with self.lock:
            return [{'address': s.peer_address, 'fingerprint': s.peer_fingerprint, 'last_active': s.last_active.isoformat(), 'queue_size': len(s.message_queue)} for s in self.sessions.values()]

    def queue_message(self, peer_address: str, message: str):
        conn = sqlite3.connect(self.db_path)
        conn.execute("INSERT INTO message_queue (peer_address, message, timestamp) VALUES (?, ?, ?)", (peer_address, message, datetime.now().isoformat()))
        conn.commit()
        conn.close()
        with self.lock:
            session = self.sessions.get(peer_address)
            if session:
                session.message_queue.append({'message': message, 'timestamp': datetime.now().isoformat()})

    def get_queued_messages(self, peer_address: str) -> List[dict]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute("SELECT id, message FROM message_queue WHERE peer_address = ? AND delivered = 0", (peer_address,))
        messages = [{'id': row[0], 'message': row[1]} for row in cursor.fetchall()]
        conn.close()
        return messages

    def mark_delivered(self, message_id: int):
        conn = sqlite3.connect(self.db_path)
        conn.execute("UPDATE message_queue SET delivered = 1 WHERE id = ?", (message_id,))
        conn.commit()
        conn.close()

    def _save_session(self, session: ChatSession):
        enc_secret = self._encrypt_secret(session.shared_secret)
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT OR REPLACE INTO sessions (peer_address, peer_fingerprint, shared_secret, last_active, send_counter, recv_counter) VALUES (?, ?, ?, ?, ?, ?)",
            (session.peer_address, session.peer_fingerprint, enc_secret, session.last_active.isoformat(), session.send_counter, session.recv_counter)
        )
        conn.commit()
        conn.close()

    def load_sessions(self):
        from hyperion.core.ratchet import DoubleRatchet
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute("SELECT peer_address, peer_fingerprint, shared_secret, last_active, send_counter, recv_counter FROM sessions")
        for row in cursor.fetchall():
            decrypted_secret = self._decrypt_secret(row[2])
            session = ChatSession(
                peer_address=row[0],
                peer_fingerprint=row[1],
                shared_secret=decrypted_secret,
                ratchet=None,
                last_active=datetime.fromisoformat(row[3]),
                send_counter=row[4],
                recv_counter=row[5]
            )
            with self.lock:
                self.sessions[session.peer_address] = session
        conn.close()

    def wipe_all(self):
        with self.lock:
            self.sessions.clear()
        conn = sqlite3.connect(self.db_path)
        conn.execute("DELETE FROM sessions")
        conn.execute("DELETE FROM message_queue")
        conn.commit()
        conn.close()