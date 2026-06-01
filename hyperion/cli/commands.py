#!/usr/bin/env python3
# hyperion_cli.py - messenger thingy
# last edited: yesterday lol

import os, sys, argparse, threading, getpass, json
from pathlib import Path
import time  # buat apa ya? lupa, tar dulu aja

# fix path biar bisa import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

try:
    from hyperion.core.client import HyperionClient
    from hyperion.core.pqc import PQC_AVAILABLE
except ImportError as e:
    print(f"import error: {e}")
    print("pastikan hyperion module keinstall bro")
    sys.exit(1)

# TODO: refactor ini nanti, msih kurang
class HyperionCLI:
    def __init__(self):
        self.client = None
        self.data_dir = os.path.expanduser("~/.hyperion")
        os.makedirs(self.data_dir, exist_ok=True)  # bikin folder kalo belum ada
        self._lock = threading.Lock()  # thread safety katanya
        
    def _log(self, msg):
        # print log dengan warna cyan
        print(f"\033[36m[LOG]\033[0m {msg}")
        
    def _on_msg(self, msg):
        # callback pas dapet pesan
        print(f"\n\033[32m[PEER]\033[0m {msg}")
        print("\033[33m[YOU]\033[0m ", end='', flush=True)
        
    def _pwd_cb(self, prompt, title):
        return getpass.getpass(f"\033[33m{prompt}: \033[0m")
    
    def cmd_host(self, args):
        # mode host/server
        if not self.client:
            self.client = HyperionClient(self._log, self._on_msg, self.data_dir)
            self.client.set_password_callback(self._pwd_cb)
            db_path = self.data_dir + "/hyperion_messages.db"
            if not os.path.exists(db_path):
                pwd = getpass.getpass("Set storage password: ")
                self.client.set_password(pwd)
                
        print("\033[36m[*] Starting Kyber-512 PQC server...\033[0m")
        
        def show_addr(addr):
            print(f"\n\033[32m[+] Your address: {addr}\033[0m")
            print("[*] Share this with your peer")
            
        self.client.start_server(show_addr)
        self._chat()
        
    def cmd_connect(self, args):
        # konek ke peer
        if not args.address:
            print("\033[31mError: address required\033[0m")
            return
            
        if not self.client:
            self.client = HyperionClient(self._log, self._on_msg, self.data_dir)
            self.client.set_password_callback(self._pwd_cb)
            # cek db
            if not os.path.exists(f"{self.data_dir}/hyperion_messages.db"):
                pwd = getpass.getpass("Set storage password: ")
                self.client.set_password(pwd)
                
        print(f"\033[36m[*] Connecting to {args.address}...\033[0m")
        
        if self.client.connect_to_peer(args.address):
            print("\033[32m[+] Connected!\033[0m")
            self._chat()
        else:
            print("\033[31m[!] Failed\033[0m")
            
    def cmd_send_file(self, args):
        # kirim file
        if not args.path:
            print("\033[31mError: file path required\033[0m")
            return
            
        if not self.client or not self.client.active_session:
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
        # emergency wipe
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
        # chat loop utama
        print("\n\033[36m[*] Chat mode. Type /help for commands.\033[0m\n")
        
        while self.client and self.client.active_session:
            try:
                msg = input("\033[33m[YOU]\033[0m ").strip()
                if not msg:
                    continue  # skip kosong
                    
                # command parsing
                if msg in ['/quit', '/exit']:
                    break
                elif msg == '/help':
                    self._help()
                elif msg == '/sessions':
                    # list semua session
                    sessions = self.client.session_manager.list_sessions()
                    for s in sessions:
                        active = ""
                        if self.client.active_session and self.client.active_session.peer_address == s['address']:
                            active = " (active)"
                        print(f"  {s['address']} - {s['fingerprint']}{active}")
                        
                elif msg.startswith('/switch '):
                    # ganti session
                    addr = msg[8:]
                    self.client.switch_session(addr)
                    
                elif msg == '/contacts':
                    if self.client.storage:
                        contacts = self.client.storage.get_contacts()
                        for c in contacts:
                            print(f"  {c['address']} - {c['fingerprint']}")
                    else:
                        print("Storage not initialized")
                        
                elif msg.startswith('/send-file '):
                    # shortcut kirim file
                    path = msg[11:]
                    self.cmd_send_file(type('Args', (), {'path': path}))
                    
                elif msg == '/fingerprint':
                    print("Your: {}".format(self.client.get_fingerprint()))
                    if self.client.active_session:
                        print("Peer: %s" % self.client.active_session.peer_fingerprint)
                        
                elif msg == '/history' or msg.startswith('/history '):
                    # show history
                    parts = msg.split()
                    limit = 50
                    if len(parts) > 1:
                        limit = int(parts[1])
                        
                    if self.client.storage:
                        history = self.client.storage.get_chat_history(self.client.active_session.peer_address, limit)
                        if not history:
                            print("No chat history")
                        else:
                            print("\n\033[36m=== Chat History ===\033[0m")
                            for h in reversed(history):
                                direction = "You" if h['direction'] == 'sent' else "Peer"
                                ts = h['timestamp']
                                print(f"  \033[33m{direction}\033[0m [{ts}]: {h['message']}")
                    else:
                        print("Storage not initialized")
                        
                elif msg == '/panic':
                    self.cmd_panic(type('Args', (), {}))
                    break
                    
                else:
                    # kirim pesan biasa
                    err = self.client.send_message(msg)
                    if err:
                        print(f"\033[31m{err}\033[0m")
                        
            except KeyboardInterrupt:
                print("\nInterrupted")
                break
            except Exception as e:
                # kadang error gajelas, print aja
                print(f"Error: {e}")
                continue
                
        print("\n\033[36m[*] Chat ended\033[0m")
        
    def _help(self):
        # print help
        help_text = """
\033[36mCommands:\033[0m
  /sessions      - List sessions
  /switch <addr> - Switch session
  /contacts      - List contacts
  /send-file <p> - Send file
  /fingerprint   - Show fingerprints
  /history [n]   - Show chat history (default 50)
  /panic         - Wipe all data
  /quit          - Exit
"""
        print(help_text)
        
    def run(self):
        # main entry point
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
    cli = HyperionCLI()
    cli.run()

if __name__ == '__main__':
    # run program
    main()
    
    # dead code below, ignore
    # print("debug mode")
    # test = HyperionCLI()
    # test._log("test")