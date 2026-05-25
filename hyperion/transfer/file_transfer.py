import os
import json
import base64
from pathlib import Path
from typing import Optional, Callable, Dict, Any, Union
from hyperion.core.ratchet import DoubleRatchet

class FileTransfer:
    CHUNK_SIZE = 512 * 1024

    def __init__(self, ratchet: DoubleRatchet, callback: Callable):
        self.ratchet = ratchet
        self.callback = callback
        self._receiving: Optional[Dict[str, Any]] = None

    def encrypt_chunk(self, data_str: str) -> str:
        return json.dumps(self.ratchet.encrypt(data_str))

    def decrypt_chunk(self, enc_data_str: str) -> str:
        return self.ratchet.decrypt(json.loads(enc_data_str))

    def send_file(self, filepath: str) -> Union[Dict, str]:
        try:
            filename = os.path.basename(filepath)
            with open(filepath, 'rb') as f:
                data = f.read()
            chunks = [data[i:i+self.CHUNK_SIZE] for i in range(0, len(data), self.CHUNK_SIZE)]
            metadata = {'type': 'file_meta', 'filename': filename, 'size': len(data), 'chunks': len(chunks)}
            return {'metadata': metadata, 'chunks': chunks, 'filename': filename}
        except Exception as e:
            return f"File read error: {e}"

    def prepare_chunk_message(self, chunk: bytes, index: int) -> str:
        chunk_data = {'type': 'file_chunk', 'index': index, 'data': base64.b64encode(chunk).decode()}
        return self.encrypt_chunk(json.dumps(chunk_data))

    def process_received_data(self, data_str: str):
        try:
            data = json.loads(data_str)
            if data.get('type') == 'file_meta':
                self._receiving = {
                    'filename': data['filename'],
                    'size': data['size'],
                    'chunks': data['chunks'],
                    'chunks_data': [None] * data['chunks'],
                    'received_count': 0
                }
                self.callback(f"FILE Receiving: {data['filename']} ({data['size']} bytes)")
            elif data.get('type') == 'file_chunk' and self._receiving:
                idx = data['index']
                if idx < len(self._receiving['chunks_data']) and self._receiving['chunks_data'][idx] is None:
                    self._receiving['chunks_data'][idx] = base64.b64decode(data['data'])
                    self._receiving['received_count'] += 1
                    progress = int(self._receiving['received_count'] / self._receiving['chunks'] * 100)
                    if progress % 10 == 0:
                        self.callback(f"FILE Progress: {progress}%")
        except Exception as e:
            self.callback(f"FILE Process error: {e}")

    def finalize_received_file(self) -> Optional[str]:
        if self._receiving and self._receiving['received_count'] == self._receiving['chunks']:
            file_data = b''.join(self._receiving['chunks_data'])
            downloads = Path.home() / 'Downloads'
            downloads.mkdir(parents=True, exist_ok=True)
            filepath = downloads / f"hyperion_{self._receiving['filename']}"
            counter = 1
            while filepath.exists():
                filepath = downloads / f"hyperion_{counter}_{self._receiving['filename']}"
                counter += 1
            with open(filepath, 'wb') as f:
                f.write(file_data)
            result = str(filepath)
            self._receiving = None
            return result
        elif self._receiving:
            missing = self._receiving['chunks'] - self._receiving['received_count']
            self.callback(f"FILE Error: Missing {missing} chunks")
            self._receiving = None
        return None