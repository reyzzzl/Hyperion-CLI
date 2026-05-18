import socket
import socks
from typing import Optional

class TorSocket:
    RECV_TIMEOUT = 60
    MAX_MESSAGE_SIZE = 50 * 1024 * 1024

    def __init__(self):
        self.sock = None
        self.use_tor = False

    def _find_tor_port(self) -> Optional[int]:
        for port in [9050, 9150]:
            try:
                test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_sock.settimeout(2)
                test_sock.connect(('127.0.0.1', port))
                test_sock.close()
                return port
            except:
                continue
        return None

    def create_server_socket(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('127.0.0.1', 9999))
        self.sock.listen(5)
        return self.sock

    def accept_connection(self, server_sock):
        server_sock.settimeout(None)
        self.sock, addr = server_sock.accept()
        self.sock.settimeout(self.RECV_TIMEOUT)
        return self.sock, addr

    def connect_via_tor(self, address: str, port: int = 80):
        tor_port = self._find_tor_port()
        if tor_port:
            self.sock = socks.socksocket()
            self.sock.set_proxy(socks.SOCKS5, '127.0.0.1', tor_port)
            self.sock.settimeout(self.RECV_TIMEOUT)
            self.sock.connect((address, port))
            self.use_tor = True
            return self.sock
        return None

    def connect_direct(self, host: str, port: int):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.RECV_TIMEOUT)
        self.sock.connect((host, port))
        self.use_tor = False
        return self.sock

    def send_all(self, data: bytes):
        total_sent = 0
        while total_sent < len(data):
            sent = self.sock.send(data[total_sent:])
            if sent == 0:
                raise ConnectionError("Connection broken")
            total_sent += sent

    def recv_all_until(self, delimiter: bytes = b'||END||') -> bytes:
        data = b''
        while not data.endswith(delimiter):
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("Connection closed")
            data += chunk
            if len(data) > self.MAX_MESSAGE_SIZE:
                raise ValueError("Message too large")
        return data[:-len(delimiter)]

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None

class TorHiddenService:
    def __init__(self, local_port: int = 9999):
        self.local_port = local_port
        self.service_id = None

    def create(self) -> Optional[str]:
        try:
            from stem.control import Controller
            for port in [9051, 9151]:
                try:
                    with Controller.from_port(port=port) as controller:
                        controller.authenticate()
                        response = controller.create_ephemeral_hidden_service({80: self.local_port}, await_publication=True)
                        self.service_id = response.service_id
                        return f"{self.service_id}.onion"
                except:
                    continue
            return None
        except ImportError:
            return None