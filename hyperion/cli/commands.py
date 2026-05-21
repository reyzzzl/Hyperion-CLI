#!/usr/bin/env python3
import os
import sys
import argparse
import getpass
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from hyperion.core.client import HyperionClient
from hyperion.core.pqc import PQC_AVAILABLE

class HyperionCLI:
    def __init__(self):
        self.client = None
        self.data_dir = os.path.expanduser("~/.hyperion")
        os.makedirs(self.data_dir, exist_ok=True)

    def _log(self, msg):
        pass

    def _on_msg(self, msg):
        print(f"\n[PEER] {msg}")
        print("[YOU] ", end='', flush=True)

    def _pwd_cb(self, prompt, title):
        return getpass.getpass(f"{prompt}: ")

    def cmd_host(self, args):
        if not self.client:
            self.client = HyperionClient(self._log, self._on_msg, self.data_dir)
            self.client.set_password_callback(self._pwd_cb)
            if not os.path.exists(f"{self.data_dir}/messages.db"):
                pwd = getpass.getpass("Set storage password: ")
                self.client.set_password(pwd)
        print("[*] Starting Kyber-512 PQC server...")
        def show_addr(addr):
            print(f"\n[+] Your address: {addr}")
            print("[*] Share this with your peer")
        self.client.start_server(show_addr)
        self._chat()

    def cmd_connect(self, args):
        if not args.address:
            print("Error: address required")
            return
        if not self.client:
            self.client = HyperionClient(self._log, self._on_msg, self.data_dir)
            self.client.set_password_callback(self._pwd_cb)
            if not os.path.exists(f"{self.data_dir}/messages.db"):
                pwd = getpass.getpass("Set storage password: ")
                self.client.set_password(pwd)
        print(f"[*] Connecting to {args.address}...")
        if self.client.connect_to_peer(args.address):
            print("[+] Connected!")
            self._chat()
        else:
            print("[!] Failed")

    def cmd_send_file(self, args):
        if not args.path:
            print("Error: file path required")
            return
        if not self.client or not self.client.active_session:
            print("Not connected")
            return
        if not os.path.exists(args.path):
            print(f"File not found: {args.path}")
            return
        print(f"[*] Sending: {os.path.basename(args.path)}...")
        res = self.client.send_file(args.path)
        if res:
            print(res)

    def cmd_panic(self, args):
        print("[!] PANIC - Wipe all data")
        confirm = input("Type 'WIPE' to confirm: ")
        if confirm != 'WIPE':
            print("Cancelled")
            return
        if self.client:
            self.client.panic()
        import shutil
        shutil.rmtree(self.data_dir, ignore_errors=True)
        print("[+] All data wiped")
        sys.exit(0)

    def _chat(self):
        print("\n[*] Chat mode. Type /help for commands.\n")
        while self.client and self.client.active_session:
            try:
                msg = input("[YOU] ").strip()
                if not msg:
                    continue
                if msg in ['/quit', '/exit']:
                    break
                elif msg == '/help':
                    self._help()
                elif msg == '/sessions':
                    for s in self.client.session_manager.list_sessions():
                        active = " (active)" if self.client.active_session and self.client.active_session.peer_address == s['address'] else ""
                        print(f"  {s['address']} - {s['fingerprint']}{active}")
                elif msg.startswith('/switch '):
                    self.client.switch_session(msg[8:])
                elif msg == '/contacts':
                    if self.client.storage:
                        for c in self.client.storage.get_contacts():
                            print(f"  {c['address']} - {c['fingerprint']}")
                elif msg.startswith('/send-file '):
                    self.cmd_send_file(type('Args', (), {'path': msg[11:]}))
                elif msg == '/fingerprint':
                    print(f"Your: {self.client.get_fingerprint()}")
                    if self.client.active_session:
                        print(f"Peer: {self.client.active_session.peer_fingerprint}")
                elif msg == '/rekey':
                    if self.client.rekey():
                        print("[+] Rekey performed")
                    else:
                        print("[-] Cannot rekey")
                elif msg == '/history' or msg.startswith('/history '):
                    parts = msg.split()
                    limit = int(parts[1]) if len(parts) > 1 else 50
                    if self.client.storage:
                        history = self.client.storage.get_chat_history(self.client.active_session.peer_address, limit)
                        if not history:
                            print("No chat history")
                        else:
                            print(f"\n=== Chat History ===")
                            for h in reversed(history):
                                direction = "You" if h['direction'] == 'sent' else "Peer"
                                print(f"  {direction} [{h['timestamp']}]: {h['message']}")
                    else:
                        print("Storage not initialized")
                else:
                    err = self.client.send_message(msg)
                    if err:
                        print(err)
            except KeyboardInterrupt:
                break
        print("\n[*] Chat ended")

    def _help(self):
        print("""
Commands:
  /sessions      - List sessions
  /switch <addr> - Switch session
  /contacts      - List contacts
  /send-file <p> - Send file
  /fingerprint   - Show fingerprints
  /rekey         - Rotate keys
  /history [n]   - Show chat history (default 50)
  /panic         - Wipe all data
  /quit          - Exit
""")

    def run(self):
        p = argparse.ArgumentParser(description='Hyperion PQC Messenger')
        sub = p.add_subparsers(dest='cmd')
        sub.add_parser('host', help='Start server')
        c = sub.add_parser('connect', help='Connect to peer')
        c.add_argument('address')
        f = sub.add_parser('send-file', help='Send file')
        f.add_argument('path')
        sub.add_parser('panic', help='Emergency wipe')
        args = p.parse_args()
        if args.cmd == 'host':
            self.cmd_host(args)
        elif args.cmd == 'connect':
            self.cmd_connect(args)
        elif args.cmd == 'send-file':
            self.cmd_send_file(args)
        elif args.cmd == 'panic':
            self.cmd_panic(args)
        else:
            p.print_help()

def main():
    HyperionCLI().run()

if __name__ == '__main__':
    main()