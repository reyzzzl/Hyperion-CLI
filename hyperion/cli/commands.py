#!/usr/bin/env python3
import os
import sys
import argparse
import threading
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
        print(f"\033[36m[LOG]\033[0m {msg}")

    def _on_msg(self, msg):
        print(f"\n\033[32m[PEER]\033[0m {msg}")
        print("\033[33m[YOU]\033[0m ", end='', flush=True)

    def _pwd_cb(self, prompt, title):
        return getpass.getpass(f"\033[33m{prompt}: \033[0m")

    def cmd_host(self, args):
        if not self.client:
            self.client = HyperionClient(self._log, self._on_msg, self.data_dir)
            self.client.set_pwd_cb(self._pwd_cb)
            if not os.path.exists(f"{self.data_dir}/messages.db"):
                pwd = getpass.getpass("Set storage password: ")
                self.client.set_pwd(pwd)
        print("\033[36m[*] Starting Kyber-512 PQC server...\033[0m")
        def show_addr(addr):
            print(f"\n\033[32m[+] Your address: {addr}\033[0m")
            print("[*] Share this with your peer")
        self.client.start_server(show_addr)
        self._chat()

    def cmd_connect(self, args):
        if not args.address:
            print("\033[31mError: address required\033[0m")
            return
        if not self.client:
            self.client = HyperionClient(self._log, self._on_msg, self.data_dir)
            self.client.set_pwd_cb(self._pwd_cb)
            if not os.path.exists(f"{self.data_dir}/messages.db"):
                pwd = getpass.getpass("Set storage password: ")
                self.client.set_pwd(pwd)
        print(f"\033[36m[*] Connecting to {args.address}...\033[0m")
        if self.client.connect(args.address):
            print("\033[32m[+] Connected!\033[0m")
            self._chat()
        else:
            print("\033[31m[!] Failed\033[0m")

    def cmd_send_file(self, args):
        if not args.path:
            print("\033[31mError: file path required\033[0m")
            return
        if not self.client or not self.client.active:
            print("\033[31mNot connected\033[0m")
            return
        if not os.path.exists(args.path):
            print(f"\033[31mFile not found: {args.path}\033[0m")
            return
        print(f"\033[36m[*] Sending: {os.path.basename(args.path)}...\033[0m")
        res = self.client.send_file(args.path)
        if res:
            print(f"\033[32m{res}\033[0m")

    def cmd_panic(self, args):
        print("\033[31m[!] PANIC - Wipe all data\033[0m")
        confirm = input("Type 'WIPE' to confirm: ")
        if confirm != 'WIPE':
            print("Cancelled")
            return
        if self.client:
            self.client.panic()
        import shutil
        shutil.rmtree(self.data_dir, ignore_errors=True)
        print("\033[32m[+] All data wiped\033[0m")
        sys.exit(0)

    def _chat(self):
        print("\n\033[36m[*] Chat mode. Type /help for commands.\033[0m\n")
        while self.client and self.client.active:
            try:
                msg = input("\033[33m[YOU]\033[0m ").strip()
                if not msg:
                    continue
                if msg in ['/quit', '/exit']:
                    break
                elif msg == '/help':
                    self._help()
                elif msg == '/sessions':
                    for s in self.client.sess_mgr.list():
                        active = " (active)" if self.client.active and self.client.active.peer_address == s['address'] else ""
                        print(f"  {s['address']} - {s['fingerprint']}{active}")
                elif msg.startswith('/switch '):
                    self.client.switch(msg[8:])
                elif msg == '/contacts':
                    for c in self.client.storage.get_contacts():
                        print(f"  {c['address']} - {c['fingerprint']}")
                elif msg.startswith('/send-file '):
                    self.cmd_send_file(type('Args', (), {'path': msg[11:]}))
                elif msg == '/fingerprint':
                    print(f"Your: {self.client.fingerprint()}")
                    if self.client.active:
                        print(f"Peer: {self.client.active.peer_fingerprint}")
                elif msg == '/rekey':
                    self.client.rekey()
                else:
                    err = self.client.send_msg(msg)
                    if err:
                        print(f"\033[31m{err}\033[0m")
            except KeyboardInterrupt:
                break
        print("\n\033[36m[*] Chat ended\033[0m")

    def _help(self):
        print("""
\033[36mCommands:\033[0m
  /sessions      - List sessions
  /switch <addr> - Switch session
  /contacts      - List contacts
  /send-file <p> - Send file
  /fingerprint   - Show fingerprints
  /rekey         - Rotate keys
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