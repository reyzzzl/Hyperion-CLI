import json
import base64
import hashlib
from typing import Tuple, Callable
from hyperion.core.identity import SecureIdentity
from hyperion.core.pqc import PQCKyber
from hyperion.transport.tor_socket import TorSocket

class Handshake:
    DELIMITER = b'||END||'

    def __init__(self, identity: SecureIdentity, pqc: PQCKyber, transport: TorSocket):
        self.identity = identity
        self.pqc = pqc
        self.transport = transport
        self.peer_fingerprint = None
        self.verified = False

    def _build_handshake_data(self) -> dict:
        pubkey = self.pqc.get_public_key()
        identity_pub = base64.b64encode(self.identity.get_public_key()).decode()
        identity_sig = base64.b64encode(self.identity.sign((pubkey + identity_pub).encode())).decode()
        return {'pqc_pubkey': pubkey, 'identity_pub': identity_pub, 'signature': identity_sig}

    def _verify_peer(self, peer_data: dict) -> bool:
        peer_identity = base64.b64decode(peer_data['identity_pub'])
        peer_fingerprint = hashlib.sha3_256(peer_identity).hexdigest()[:16]
        valid = self.identity.verify(
            base64.b64decode(peer_data['signature']),
            (peer_data['pqc_pubkey'] + peer_data['identity_pub']).encode(),
            peer_identity
        )
        if valid:
            self.peer_fingerprint = peer_fingerprint
            self.verified = True
        return valid

    def server_handshake(self, status_callback: Callable) -> bytes:
        status_callback("[*] Sending public key...")
        data = json.dumps(self._build_handshake_data())
        self.transport.send_all(data.encode() + self.DELIMITER)
        status_callback("[*] Waiting for client public key...")
        peer_data = json.loads(self.transport.recv_all_until().decode())
        if not self._verify_peer(peer_data):
            status_callback("[!] Peer verification failed - aborting handshake")
            raise ValueError("Peer verification failed")
        status_callback(f"[+] Peer verified: {self.peer_fingerprint}")
        status_callback("[*] Waiting for ciphertext...")
        ciphertext = self.transport.recv_all_until().decode()
        return ciphertext

    def client_handshake(self, status_callback: Callable) -> Tuple[bytes, str]:
        status_callback("[*] Waiting for server public key...")
        peer_data = json.loads(self.transport.recv_all_until().decode())
        if not self._verify_peer(peer_data):
            status_callback("[!] Peer verification failed - aborting handshake")
            raise ValueError("Peer verification failed")
        status_callback(f"[+] Peer verified: {self.peer_fingerprint}")
        status_callback("[*] Encapsulating secret...")
        shared_secret, ciphertext = self.pqc.encapsulate(peer_data['pqc_pubkey'])
        status_callback("[*] Sending public key...")
        data = json.dumps(self._build_handshake_data())
        self.transport.send_all(data.encode() + self.DELIMITER)
        status_callback("[*] Sending ciphertext...")
        self.transport.send_all(ciphertext.encode() + self.DELIMITER)
        return shared_secret, ciphertext

    def get_peer_fingerprint(self) -> str:
        return self.peer_fingerprint if self.peer_fingerprint else "Unknown"