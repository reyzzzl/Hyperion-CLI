import sqlite3
import base64
import secrets
import os
from typing import List, Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

class EncryptedStorage:
    def __init__(self, db_path: str = "hyperion_messages.db", password: str = None):
        self.db_path = db_path
        self.password = password
        self.key = None
        self.salt_path = db_path.replace('.db', '.salt')
        if password:
            self._derive_key()
        self._init_db()

    def _derive_key(self):
        if os.path.exists(self.salt_path):
            with open(self.salt_path, 'rb') as f:
                salt = f.read()
        else:
            salt = secrets.token_bytes(32)
            with open(self.salt_path, 'wb') as f:
                f.write(salt)
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
        self.key = kdf.derive(self.password.encode())

    def _encrypt(self, data: str) -> str:
        if not self.key:
            return data
        iv = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES256(self.key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
        combined = iv + encryptor.tag + ciphertext
        return base64.b64encode(combined).decode()

    def _decrypt(self, enc_data: str) -> str:
        if not self.key:
            return enc_data
        raw = base64.b64decode(enc_data)
        iv = raw[:12]
        tag = raw[12:28]
        ciphertext = raw[28:]
        cipher = Cipher(algorithms.AES256(self.key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute('CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, peer_address TEXT, direction TEXT, message TEXT, timestamp TIMESTAMP, delivered BOOLEAN DEFAULT 1)')
        conn.execute('CREATE TABLE IF NOT EXISTS contacts (peer_address TEXT PRIMARY KEY, peer_fingerprint TEXT, alias TEXT, last_seen TIMESTAMP, trusted BOOLEAN DEFAULT 0)')
        conn.commit()
        conn.close()

    def save_message(self, peer_address: str, direction: str, message: str):
        encrypted = self._encrypt(message)
        conn = sqlite3.connect(self.db_path)
        conn.execute("INSERT INTO messages (peer_address, direction, message, timestamp) VALUES (?, ?, ?, CURRENT_TIMESTAMP)", (peer_address, direction, encrypted))
        conn.commit()
        conn.close()

    def get_chat_history(self, peer_address: str, limit: int = 100) -> List[dict]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute("SELECT direction, message, timestamp FROM messages WHERE peer_address = ? ORDER BY timestamp DESC LIMIT ?", (peer_address, limit))
        messages = [{'direction': row[0], 'message': self._decrypt(row[1]), 'timestamp': row[2]} for row in cursor.fetchall()]
        conn.close()
        return messages

    def save_contact(self, peer_address: str, peer_fingerprint: str, alias: str = None):
        conn = sqlite3.connect(self.db_path)
        conn.execute("INSERT OR REPLACE INTO contacts (peer_address, peer_fingerprint, alias, last_seen, trusted) VALUES (?, ?, ?, CURRENT_TIMESTAMP, 0)", (peer_address, peer_fingerprint, alias))
        conn.commit()
        conn.close()

    def get_contacts(self) -> List[dict]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute("SELECT peer_address, peer_fingerprint, alias, last_seen, trusted FROM contacts")
        contacts = [{'address': row[0], 'fingerprint': row[1], 'alias': row[2], 'last_seen': row[3], 'trusted': row[4]} for row in cursor.fetchall()]
        conn.close()
        return contacts

    def trust_contact(self, peer_address: str):
        conn = sqlite3.connect(self.db_path)
        conn.execute("UPDATE contacts SET trusted = 1 WHERE peer_address = ?", (peer_address,))
        conn.commit()
        conn.close()

    def delete_history(self, peer_address: str):
        conn = sqlite3.connect(self.db_path)
        conn.execute("DELETE FROM messages WHERE peer_address = ?", (peer_address,))
        conn.commit()
        conn.close()

    def wipe_all(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("DELETE FROM messages")
        conn.execute("DELETE FROM contacts")
        conn.commit()
        conn.close()
        if os.path.exists(self.salt_path):
            os.remove(self.salt_path)