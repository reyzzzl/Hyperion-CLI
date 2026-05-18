import sqlite3
import json
import threading
from dataclasses import dataclass, field
from typing import Dict, Optional, List
from datetime import datetime

@dataclass
class ChatSession:
    peer_address: str
    peer_fingerprint: str
    shared_secret: bytes
    ratchet: 'DoubleRatchet'
    last_active: datetime = field(default_factory=datetime.now)
    message_queue: List[dict] = field(default_factory=list)

class SessionManager:
    def __init__(self, db_path: str = "hyperion_sessions.db"):
        self.sessions: Dict[str, ChatSession] = {}
        self.lock = threading.Lock()
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute('CREATE TABLE IF NOT EXISTS sessions (peer_address TEXT PRIMARY KEY, peer_fingerprint TEXT, shared_secret BLOB, last_active TIMESTAMP)')
        conn.execute('CREATE TABLE IF NOT EXISTS message_queue (id INTEGER PRIMARY KEY AUTOINCREMENT, peer_address TEXT, message TEXT, timestamp TIMESTAMP, delivered BOOLEAN DEFAULT 0)')
        conn.commit()
        conn.close()

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
        conn = sqlite3.connect(self.db_path)
        conn.execute("INSERT OR REPLACE INTO sessions (peer_address, peer_fingerprint, shared_secret, last_active) VALUES (?, ?, ?, ?)", (session.peer_address, session.peer_fingerprint, session.shared_secret, session.last_active.isoformat()))
        conn.commit()
        conn.close()

    def load_sessions(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute("SELECT peer_address, peer_fingerprint, shared_secret, last_active FROM sessions")
        for row in cursor.fetchall():
            session = ChatSession(peer_address=row[0], peer_fingerprint=row[1], shared_secret=row[2], ratchet=None, last_active=datetime.fromisoformat(row[3]))
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
