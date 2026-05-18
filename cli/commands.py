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
        self.running = True
        self.data_dir = os.path.expanduser("~/.hyperion")
        os.makedirs(self.data_dir, exist_ok=True)

    def _log(self, msg):
        print(f"\033[36m[LOG]\033[0m {msg}")

    def _on_message(self, msg):
        print(f"\n\033[32m[PEER]\033[0m {msg}")
        print("\033[33m[YOU]\033[0m ", end='', flush=True)

    def _password_callback(self, prompt, title):
        return getpass.getpass(f"\033[33m{prompt}: \033[0m")

    def _show_help(self):
        print("""
\033[36m=== Hyperion CLI Commands ===\033[0m

\033[33mSession Management:\033[0m
  /sessions              - List all saved sessions
  /switch <address>      - Switch to a different session
  /active                - Show current active session

\033[33mChat Commands:\033[0m
  /rekey                 - Manual key rotation
  /fingerprint           - Show identity fingerprints
  /history [limit]       - Show chat history
  /clear                 - Clear chat history with current peer

\033[33mContact Management:\033[0m
  /contacts              - List all contacts
  /trust <address>       - Mark contact as trusted
  /alias <address> <name>- Set alias for contact

\033[33mFile Transfer:\033[0m
  /send-file <path>      - Send a file

\033[33mSecurity:\033[0m
  /panic                 - Emergency wipe all data
  /status                - Show connection status

\033[33mOther:\033[0m
  /help                  - Show this help
  /quit, /exit           - Exit application

\033[33m(Just type any message to send to current peer)\033[0m
        """)

    def cmd_host(self, args):
        if not self.client:
            self.client = HyperionClient(self._log, self._on_message, self.data_dir)
            self.client.set_password_callback(self._password_callback)
            if not os.path.exists(f"{self.data_dir}/hyperion_messages.db"):
                pwd = getpass.getpass("Set storage password: ")
                self.client.set_password(pwd)
        print("\033[36m[*] Starting Kyber-512 PQC server...\033[0m")
        def show_address(addr):
            print(f"\n\033[32m[+] Your address: {addr}\033[0m")
            print("[*] Share this with your peer")
            print("[*] Waiting for connection...\n")
        self.client.start_server(show_address)
        self._chat_loop()

    def cmd_connect(self, args):
        if not args.address:
            print("\033[31mError: Please provide address\033[0m")
            return
        if not self.client:
            self.client = HyperionClient(self._log, self._on_message, self.data_dir)
            self.client.set_password_callback(self._password_callback)
            if not os.path.exists(f"{self.data_dir}/hyperion_messages.db"):
                pwd = getpass.getpass("Set storage password: ")
                self.client.set_password(pwd)
        print(f"\033[36m[*] Connecting to {args.address}...\033[0m")
        success = self.client.connect_to_peer(args.address)
        if success:
            print("\033[32m[+] Connected! Secure channel established.\033[0m")
            self._chat_loop()
        else:
            print("\033[31m[!] Connection failed\033[0m")

    def cmd_sessions(self, args):
        if not self.client:
            print("\033[31mClient not initialized\033[0m")
            return
        sessions = self.client.get_sessions()
        if not sessions:
            print("No saved sessions")
            return
        print("\n\033[36m=== Saved Sessions ===\033[0m")
        for s in sessions:
            active = " (active)" if self.client.active_session and self.client.active_session.peer_address == s['address'] else ""
            print(f"  {s['address']} - {s['fingerprint']} - Last: {s['last_active']}{active}")

    def cmd_switch(self, args):
        if not args.address:
            print("\033[31mError: Please provide address\033[0m")
            return
        if not self.client:
            print("\033[31mClient not initialized\033[0m")
            return
        if self.client.switch_session(args.address):
            print(f"\033[32m[+] Switched to session with {args.address}\033[0m")
        else:
            print(f"\033[31m[-] Session not found: {args.address}\033[0m")

    def cmd_active(self, args):
        if not self.client:
            print("\033[31mClient not initialized\033[0m")
            return
        session = self.client.get_active_session()
        if session:
            print(f"\nActive session: {session['address']}")
            print(f"  Fingerprint: {session['fingerprint']}")
            print(f"  Last active: {session['last_active']}")
        else:
            print("No active session")

    def cmd_contacts(self, args):
        if not self.client or not self.client.storage:
            print("\033[31mStorage not initialized\033[0m")
            return
        contacts = self.client.get_contacts()
        if not contacts:
            print("No contacts")
            return
        print("\n\033[36m=== Contacts ===\033[0m")
        for c in contacts:
            alias = f" ({c['alias']})" if c['alias'] else ""
            trusted = " [TRUSTED]" if c['trusted'] else ""
            print(f"  {c['address']}{alias} - {c['fingerprint']}{trusted}")

    def cmd_trust(self, args):
        if not args.address:
            print("\033[31mError: Please provide address\033[0m")
            return
        if not self.client or not self.client.storage:
            print("\033[31mStorage not initialized\033[0m")
            return
        self.client.storage.trust_contact(args.address)
        print(f"\033[32m[+] Contact {args.address} marked as trusted\033[0m")

    def cmd_alias(self, args):
        if not args.address or not args.name:
            print("\033[31mError: Usage: /alias <address> <name>\033[0m")
            return
        if not self.client or not self.client.storage:
            print("\033[31mStorage not initialized\033[0m")
            return
        self.client.storage.save_contact(args.address, "", args.name)
        print(f"\033[32m[+] Alias set: {args.address} -> {args.name}\033[0m")

    def cmd_history(self, args):
        if not self.client or not self.client.active_session:
            print("\033[31mNo active session\033[0m")
            return
        limit = int(args.limit) if args.limit else 50
        history = self.client.get_chat_history(self.client.active_session.peer_address, limit)
        if not history:
            print("No chat history")
            return
        print(f"\n\033[36m=== Chat History with {self.client.active_session.peer_address} ===\033[0m")
        for msg in reversed(history):
            direction = "You" if msg['direction'] == 'sent' else "Peer"
            print(f"  \033[33m{direction}\033[0m [{msg['timestamp']}]: {msg['message']}")

    def cmd_clear(self, args):
        if not self.client or not self.client.active_session:
            print("\033[31mNo active session\033[0m")
            return
        confirm = input(f"Clear all messages with {self.client.active_session.peer_address}? (y/N): ")
        if confirm.lower() == 'y':
            self.client.storage.delete_history(self.client.active_session.peer_address)
            print("\033[32m[+] Chat history cleared\033[0m")

    def cmd_send_file(self, args):
        if not args.filepath:
            print("\033[31mError: Please provide file path\033[0m")
            return
        if not self.client or not self.client.active_session:
            print("\033[31mNo active session\033[0m")
            return
        if not os.path.exists(args.filepath):
            print(f"\033[31mFile not found: {args.filepath}\033[0m")
            return
        print(f"\033[36m[*] Sending file: {os.path.basename(args.filepath)}...\033[0m")
        result = self.client.send_file(args.filepath)
        if result:
            print(f"\033[32m{result}\033[0m")

    def cmd_fingerprint(self, args):
        if not self.client or not self.client.identity:
            print("\033[31mClient not initialized\033[0m")
            return
        print(f"\nYour fingerprint: \033[32m{self.client.get_fingerprint()}\033[0m")
        if self.client.active_session:
            print(f"Peer fingerprint: \033[33m{self.client.active_session.peer_fingerprint}\033[0m")

    def cmd_rekey(self, args):
        if not self.client:
            print("\033[31mClient not initialized\033[0m")
            return
        if self.client.rekey():
            print("\033[32m[+] Manual rekey performed\033[0m")
        else:
            print("\033[31m[-] Cannot rekey - not connected\033[0m")

    def cmd_status(self, args):
        if not self.client:
            print("Status: Not initialized")
            return
        print(f"\n\033[36m=== Status ===\033[0m")
        print(f"  Connected: {self.client.active_session is not None}")
        print(f"  Identity: {self.client.get_fingerprint()}")
        if self.client.active_session:
            print(f"  Active peer: {self.client.active_session.peer_address}")
            print(f"  Peer fingerprint: {self.client.active_session.peer_fingerprint}")

    def cmd_panic(self, args):
        print("\033[31m[!] PANIC BUTTON - Wiping all secure data...\033[0m")
        confirm = input("Type 'WIPE' to confirm: ")
        if confirm != 'WIPE':
            print("Cancelled")
            return
        if self.client:
            self.client.panic()
        import shutil
        shutil.rmtree(self.data_dir, ignore_errors=True)
        print("\033[32m[+] All keys and data wiped\033[0m")
        print("[+] Exiting...")
        self.running = False
        sys.exit(0)

    def _chat_loop(self):
        print("\n\033[36m[*] Entering chat mode. Type '/help' for commands.\033[0m\n")
        while self.running and self.client and self.client.active_session:
            try:
                msg = input("\033[33m[YOU]\033[0m ").strip()
                if not msg:
                    continue
                if msg == '/quit' or msg == '/exit':
                    break
                elif msg == '/help':
                    self._show_help()
                elif msg == '/sessions':
                    self.cmd_sessions(None)
                elif msg.startswith('/switch '):
                    self.cmd_switch(type('Args', (), {'address': msg[8:]}))
                elif msg == '/active':
                    self.cmd_active(None)
                elif msg == '/contacts':
                    self.cmd_contacts(None)
                elif msg.startswith('/trust '):
                    self.cmd_trust(type('Args', (), {'address': msg[7:]}))
                elif msg.startswith('/alias '):
                    parts = msg[7:].split(' ', 1)
                    if len(parts) == 2:
                        self.cmd_alias(type('Args', (), {'address': parts[0], 'name': parts[1]}))
                elif msg.startswith('/history'):
                    parts = msg.split()
                    limit = parts[1] if len(parts) > 1 else None
                    self.cmd_history(type('Args', (), {'limit': limit}))
                elif msg == '/clear':
                    self.cmd_clear(None)
                elif msg.startswith('/send-file '):
                    self.cmd_send_file(type('Args', (), {'filepath': msg[11:]}))
                elif msg == '/fingerprint':
                    self.cmd_fingerprint(None)
                elif msg == '/rekey':
                    self.cmd_rekey(None)
                elif msg == '/status':
                    self.cmd_status(None)
                elif msg == '/panic':
                    self.cmd_panic(None)
                else:
                    error = self.client.send_message(msg)
                    if error:
                        print(f"\033[31m{error}\033[0m")
            except KeyboardInterrupt:
                print("\n\033[36m[*] Interrupted\033[0m")
                break
            except EOFError:
                break
        print("\n\033[36m[*] Exiting chat mode\033[0m")

    def run(self):
        parser = argparse.ArgumentParser(description='Hyperion PQC - Post-Quantum Secure Messenger (CLI)')
        subparsers = parser.add_subparsers(dest='command', help='Commands')
        subparsers.add_parser('host', help='Start server mode')
        connect_parser = subparsers.add_parser('connect', help='Connect to peer')
        connect_parser.add_argument('address', help='Peer address (IP:port or .onion)')
        sendfile_parser = subparsers.add_parser('send-file', help='Send file')
        sendfile_parser.add_argument('filepath', help='Path to file')
        subparsers.add_parser('panic', help='Emergency wipe and exit')
        args = parser.parse_args()
        if args.command == 'host':
            self.cmd_host(args)
        elif args.command == 'connect':
            self.cmd_connect(args)
        elif args.command == 'send-file':
            self.cmd_send_file(args)
        elif args.command == 'panic':
            self.cmd_panic(args)
        else:
            parser.print_help()

def main():
    cli = HyperionCLI()
    cli.run()

if __name__ == '__main__':
    main()

