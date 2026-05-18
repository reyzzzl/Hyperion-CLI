import json
import threading
import socket
import base64
from typing import Callable, Optional, List
from datetime import datetime
from hyperion.core.identity import SecureIdentity
from hyperion.core.pqc import PQCKyber, PQC_AVAILABLE
from hyperion.core.ratchet import DoubleRatchet
from hyperion.core.session import SessionManager, ChatSession
from hyperion.core.storage import EncryptedStorage
from hyperion.transport.tor_socket import TorSocket, TorHiddenService
from hyperion.protocol.handshake import Handshake
from hyperion.transfer.file_transfer import FileTransfer

class HyperionClient:
    DELIMITER = b'||END||'
    FILE_DELIMITER = b'||FILE||'
    REHANDSHAKE_DELIMITER = b'||REKEY||'

    def __init__(self, log_callback: Callable[[str], None], message_callback: Callable[[str], None], data_dir: str = "."):
        self.log_callback = log_callback
        self.message_callback = message_callback
        self.data_dir = data_dir
        self.identity = None
        self.pqc = None
        self.session_manager = SessionManager(f"{data_dir}/hyperion_sessions.db")
        self.storage = None
        self.active_session: Optional[ChatSession] = None
        self.transport = TorSocket()
        self.running = True
        self._receive_thread = None
        self._server_socket = None
        self._rehandshake_lock = threading.RLock()
        if PQC_AVAILABLE:
            self.pqc = PQCKyber()
            self.log_callback("[+] PQC Kyber-512 available")
        else:
            self.log_callback("[!] PQC Kyber-512 not available (install liboqs-python)")

    def set_password(self, password: str):
        self.storage = EncryptedStorage(f"{self.data_dir}/hyperion_messages.db", password)

    def set_password_callback(self, callback: Callable[[str, str], Optional[str]]):
        self.identity = SecureIdentity(f"{self.data_dir}/hyperion_identity.json", password_callback=callback)
        self.session_manager.load_sessions()

    def get_fingerprint(self) -> str:
        return self.identity.get_fingerprint() if self.identity else "No identity"

    def get_sessions(self) -> List[dict]:
        return self.session_manager.list_sessions()

    def get_contacts(self) -> List[dict]:
        return self.storage.get_contacts() if self.storage else []

    def get_chat_history(self, peer_address: str, limit: int = 100) -> List[dict]:
        return self.storage.get_chat_history(peer_address, limit) if self.storage else []

    def _start_receive_loop(self):
        def receive():
            while self.running:
                try:
                    data = self.transport.recv_all_until()
                    if data.startswith(self.FILE_DELIMITER):
                        self._handle_file_data(data)
                    elif data.startswith(self.REHANDSHAKE_DELIMITER):
                        self._handle_rehandshake(data)
                    else:
                        self._handle_message(data)
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.log_callback(f"Receive error: {e}")
                    break
        self._receive_thread = threading.Thread(target=receive, daemon=True)
        self._receive_thread.start()
        self.log_callback("[*] Receive loop started")

    def _handle_message(self, data: bytes):
        decrypted = self.active_session.ratchet.decrypt(json.loads(data.decode()))
        if self.storage:
            self.storage.save_message(self.active_session.peer_address, "received", decrypted)
        queued = self.session_manager.get_queued_messages(self.active_session.peer_address)
        for q in queued:
            self.active_session.ratchet.encrypt(q['message'])
            self.session_manager.mark_delivered(q['id'])
        self.message_callback(decrypted)

    def _handle_file_data(self, data: bytes):
        if not self.active_session:
            return
        if data == self.FILE_DELIMITER + b'END' + self.FILE_DELIMITER:
            if hasattr(self, '_file_transfer'):
                result = self._file_transfer.finalize_received_file()
                if result:
                    self.log_callback(f"FILE Saved to: {result}")
            self.log_callback("FILE Transfer complete")
        else:
            meta_str = data[len(self.FILE_DELIMITER):-len(self.DELIMITER)].decode()
            decrypted = self.active_session.ratchet.decrypt(json.loads(meta_str))
            if hasattr(self, '_file_transfer'):
                self._file_transfer.process_received_data(decrypted)

    def _handle_rehandshake(self, data: bytes):
        self.log_callback("[*] Peer requested rekey, performing re-handshake...")
        threading.Thread(target=self._perform_rehandshake, daemon=True).start()

    def _perform_rehandshake(self):
        with self._rehandshake_lock:
            if not self.active_session:
                return
            old_pqc = self.pqc
            self.pqc = PQCKyber()
            self.pqc._init_kem()
            pubkey = self.pqc.get_public_key()
            identity_pub = base64.b64encode(self.identity.get_public_key()).decode()
            identity_sig = base64.b64encode(self.identity.sign((pubkey + identity_pub).encode())).decode()
            rekey_data = json.dumps({'type': 'rekey', 'pqc_pubkey': pubkey, 'identity_pub': identity_pub, 'signature': identity_sig})
            self.transport.send_all(self.REHANDSHAKE_DELIMITER + rekey_data.encode() + self.DELIMITER)
            peer_data = json.loads(self.transport.recv_all_until().decode())
            ciphertext = peer_data['ciphertext']
            kyber_secret = self.pqc.decapsulate(ciphertext)
            root_key = self.pqc.derive_root_key(kyber_secret)
            self.active_session.ratchet = DoubleRatchet(root_key, self._auto_rekey_callback)
            self.active_session.shared_secret = root_key
            self.active_session.last_active = datetime.now()
            self.log_callback("[+] Re-handshake completed, new keys active")

    def _auto_rekey_callback(self):
        self.log_callback("[*] Auto-rekey triggered, performing re-handshake...")
        threading.Thread(target=self._perform_rehandshake, daemon=True).start()

    def start_server(self, address_callback: Callable[[str], None]):
        if not self.pqc:
            self.log_callback("[!] PQC not available")
            return
        self.log_callback("[*] Generating Kyber-512 keys...")
        self.pqc._init_kem()
        self.log_callback(f"[*] Identity: {self.get_fingerprint()}")
        self.log_callback("[*] Creating Tor hidden service...")
        tor_hs = TorHiddenService()
        onion = tor_hs.create()
        if onion:
            address_callback(onion)
            self.log_callback(f"[+] Hidden service: {onion}")
        else:
            self.log_callback("[!] Tor not available, using local mode")
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            address_callback(f"{local_ip}:9999")
        self.log_callback("[*] Waiting for connection...")
        self._server_socket = self.transport.create_server_socket()
        self.transport.accept_connection(self._server_socket)
        self.log_callback("[+] Client connected")
        self._complete_handshake()

    def connect_to_peer(self, address: str) -> bool:
        if not self.pqc:
            self.log_callback("[!] PQC not available")
            return False
        existing = self.session_manager.get_session(address)
        if existing and existing.ratchet:
            self.log_callback(f"[*] Reusing existing session with {address}")
            self.active_session = existing
            self._start_receive_loop()
            return True
        self.log_callback(f"[*] Connecting to {address}...")
        is_onion = '.onion' in address.lower()
        if is_onion:
            result = self.transport.connect_via_tor(address, 80)
            if result:
                self.log_callback("[+] Connected via Tor")
            else:
                self.log_callback("[!] Tor not available")
                return False
        else:
            parts = address.split(':')
            host = parts[0]
            port = int(parts[1]) if len(parts) > 1 else 9999
            self.transport.connect_direct(host, port)
            self.log_callback("[+] Connected directly")
        self._complete_handshake(address)
        return True

    def _complete_handshake(self, peer_address: str = None):
        handshake = Handshake(self.identity, self.pqc, self.transport)
        if peer_address:
            shared_secret, _ = handshake.client_handshake(self.log_callback)
            root_key = self.pqc.derive_root_key(shared_secret)
            ratchet = DoubleRatchet(root_key, self._auto_rekey_callback)
            self.active_session = ChatSession(peer_address=peer_address, peer_fingerprint=handshake.get_peer_fingerprint(), shared_secret=root_key, ratchet=ratchet, last_active=datetime.now())
        else:
            ciphertext = handshake.server_handshake(self.log_callback)
            kyber_secret = self.pqc.decapsulate(ciphertext)
            root_key = self.pqc.derive_root_key(kyber_secret)
            ratchet = DoubleRatchet(root_key, self._auto_rekey_callback)
            self.active_session = ChatSession(peer_address="unknown", peer_fingerprint=handshake.get_peer_fingerprint(), shared_secret=root_key, ratchet=ratchet, last_active=datetime.now())
        self.session_manager.add_session(self.active_session)
        if self.storage:
            self.storage.save_contact(self.active_session.peer_address, self.active_session.peer_fingerprint)
        self._file_transfer = FileTransfer(ratchet, self.log_callback)
        self.log_callback("[+] Secure channel established")
        if handshake.verified:
            self.log_callback(f"[+] Peer verified: {self.active_session.peer_fingerprint}")
        queued = self.session_manager.get_queued_messages(self.active_session.peer_address)
        for q in queued:
            self.send_message(q['message'])
            self.session_manager.mark_delivered(q['id'])
        self._start_receive_loop()

    def send_message(self, message: str) -> Optional[str]:
        if not self.active_session or not self.active_session.ratchet:
            if self.active_session:
                self.session_manager.queue_message(self.active_session.peer_address, message)
                return "Message queued (peer offline)"
            return "Not connected"
        try:
            encrypted = json.dumps(self.active_session.ratchet.encrypt(message))
            self.transport.send_all(encrypted.encode() + self.DELIMITER)
            if self.storage:
                self.storage.save_message(self.active_session.peer_address, "sent", message)
            return None
        except Exception as e:
            if self.active_session:
                self.session_manager.queue_message(self.active_session.peer_address, message)
                return f"Message queued (send error: {e})"
            return f"Send error: {e}"

    def send_file(self, filepath: str) -> Optional[str]:
        if not self.active_session or not self.active_session.ratchet:
            return "Not connected"
        result = self._file_transfer.send_file(filepath)
        if isinstance(result, dict):
            metadata = result['metadata']
            self.transport.send_all(self.FILE_DELIMITER + json.dumps(self.active_session.ratchet.encrypt(json.dumps(metadata))).encode() + self.DELIMITER)
            for i, chunk in enumerate(result['chunks']):
                msg = self._file_transfer.prepare_chunk_message(chunk, i)
                self.transport.send_all(msg.encode() + self.DELIMITER)
            self.transport.send_all(self.FILE_DELIMITER + b'END' + self.FILE_DELIMITER)
            return f"File sent: {result['filename']}"
        return result

    def switch_session(self, peer_address: str) -> bool:
        session = self.session_manager.get_session(peer_address)
        if not session:
            self.log_callback(f"[!] No session found for {peer_address}")
            return False
        self.active_session = session
        self.log_callback(f"[*] Switched to session with {peer_address}")
        return True

    def get_active_session(self) -> Optional[dict]:
        if self.active_session:
            return {'address': self.active_session.peer_address, 'fingerprint': self.active_session.peer_fingerprint, 'last_active': self.active_session.last_active.isoformat()}
        return None

    def rekey(self):
        if self.active_session and self.active_session.ratchet:
            self.active_session.ratchet.rekey()
            return True
        return False

    def panic(self):
        self.log_callback("[!] PANIC MODE - Wiping all secure data")
        self.running = False
        if self.active_session:
            self.active_session.ratchet.wipe_memory()
        if self.identity:
            self.identity.wipe_memory()
        if self.pqc:
            self.pqc.cleanup()
        if self.session_manager:
            self.session_manager.wipe_all()
        if self.storage:
            self.storage.wipe_all()
        self.transport.close()
        self.log_callback("[+] All keys and data wiped from disk and memory")
        return True

    def close(self):
        self.running = False
        if self.pqc:
            self.pqc.cleanup()
        self.transport.close()