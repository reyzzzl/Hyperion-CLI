# Hyperion PQC
> bugs are being fixed, please don't install yet 

![Status Update](https://img.shields.io/badge/Status-v2-red.svg)
![Type CLI--Application](https://img.shields.io/badge/Type-CLI%20Application-blue.svg)
![Crypto Kyber--512%20%7C%20ML--KEM](https://img.shields.io/badge/Crypto-Kyber--512%20%7C%20ML--KEM-orange)
![Network Tor%20Onion%20Routing](https://img.shields.io/badge/Network-Tor%20Onion%20Routing-purple)
![Python Version](https://img.shields.io/badge/Python-3.9+-blue)

**Post-Quantum Encrypted Messenger — Built for the Open Internet**

---

> "Privacy is not about having something to hide. It's about having something to protect."

## 📌 What is This?

**Hyperion** is a peer-to-peer encrypted messenger built around one idea: *your conversations belong to you, and only you.* It uses **post-quantum cryptography** — the kind that stays secure even against future quantum computers — combined with **onion routing via Tor** to give you a private channel that's both technically strong and philosophically honest.

Hyperion v2.0.0 has been completely overhauled into a fully modular Python package featuring an interactive CLI terminal interface, encrypted local persistent databases, offline message queues, and a multi-factor key derivation architecture.

Everything here is open source under **GPL-3.0**. You can read it, run it, audit it, fork it, break it, and improve it.

---

## ⚡ v2.0.0 New Features & Innovations

### 1. Complete Post-Quantum Cryptography (PQC) Stack
Hyperion now utilizes a dual-layer quantum security ecosystem via `liboqs` to resist both classical attacks and future quantum decryption vectors (Shor's and Grover's algorithms).

| Component | Legacy Framework | Hyperion v2.0.0 (Current) | Quantum Resistance |
| :--- | :--- | :--- | :--- |
| **Key Exchange** | Classical ECDH | **Kyber-512** (NIST ML-KEM) | ✅ Yes |
| **Signature** | Classical Ed25519 | **Dilithium5** (NIST ML-DSA) | ✅ Yes |

### 2. Multi-Factor Key Derivation (MultiKDF)
To prevent master password brute-forcing at rest, Hyperion implements a hybrid multi-factor extraction system cascading 3 distinct KDF functions mapped via XOR operations:

```text
Final Key = Argon2id XOR Scrypt XOR PBKDF2

```
 * **Argon2id:** Memory-hard parameter profiling to neutralize ASIC acceleration.
 * **Scrypt:** Memory-hard parameter profiling designed to resist massive GPU arrays.
 * **PBKDF2:** CPU-hard function configured with high iteration counts to slow down sequential CPU scaling.
 * *Advantage:* Breaking the storage database requires an attacker to successfully breach three mathematically distinct cryptographic algorithms simultaneously.
### 3. Persistent Session Management
Unlike temporary P2P links, Hyperion v2.0.0 introduces structural session persistence backed by local database architectures.
| Feature | Technical Description |
|---|---|
| **Multi-session Layout** | Allows concurrent decoupled chat interactions across multiple unique peers. |
| **SQLite Persistence** | Session tokens are safely cached on disk, permitting immediate resume across app restarts without executing a new handshake sequence. |
| **Encrypted Storage** | Active conversation rows are heavily shielded at rest using **AES-256-GCM**. |
| **Random Salt Mapping** | Every individual local storage file provisions an isolated unique cryptographic salt layer. |
### 4. Offline Message Queue
No more dropped payloads when a peer goes offline. Hyperion temporarily routes sessional traffic through an isolated message queue.
```text
Peer Offline ──> Payload Cached in Local SQLite Queue ──> Sent Automatically Upon Reconnection

```
### 5. Automated Background Re-handshake
To maximize Perfect Forward Secrecy, key rotation is executed asynchronously in the background via strict structural boundaries, drastically limiting message exposure windows:
| Trigger Vector | Threshold Barrier |
|---|---|
| **Message Volume** | Triggers automatically every **100 messages** sent/received. |
| **Temporal Duration** | Triggers automatically every **10 minutes** of active runtime. |
| **Manual Override** | Executed instantly by running the /rekey command. |
### 6. Deadlock-Free Double Ratchet
The underlying core Double Ratchet engine now integrates a threading.RLock() (Reentrant Lock) architecture. This patch eliminates race conditions and potential thread deadlocks when multiple automated triggers attempt to spin up a background re-handshake concurrently.
## 🛠️ Cryptographic Stack
| Primitive / Protocol | Role | Details & Context |
|---|---|---|
| **CRYSTALS-Kyber (Kyber-512)** | Key Enapsulation (KEM) | Based on Module Learning With Errors (MLWE). Standardized as **FIPS 203**. Implemented via liboqs. |
| **Double Ratchet** | Symmetric Key Management | Inspired by Signal Protocol. Hashes chain keys forward with SHA3-256 after every message to prevent backward reconstruction. |
| **AES-256-GCM** | Authenticated Encryption | Provides confidentiality and integrity. The authentication tag is verified *before* decryption to prevent tampering. |
| **Ed25519** | Identity Signatures | Signs the handshake payload to prevent Man-in-the-Middle (MitM) attacks. Fast, compact, and trusted. |
| **MultiKDF (Argon2 / Scrypt / PBKDF2)** | Master Key Derivation | Cascades three hardened functions via XOR mapping (Argon2id ^ Scrypt ^ PBKDF2) to encrypt database headers at rest. |
| **SQLite3 (AES-256-GCM Layer)** | Encrypted Local Storage | Encrypts rows for transaction history (hyperion_messages.db) and sessions (hyperion_sessions.db) on disk. |
## 💻 Supported Environments
| Environment | Status | Configuration Notes |
|---|---|---|
| **VPS (Ubuntu/Debian)** | ✅ Full | Recommended deployment target. Supports background Tor services natively. |
| **Termux (Android)** | ✅ Full | No root required. Fully functional post-quantum terminal environment. |
| **Local Linux / macOS** | ✅ Full | Ideal environment for rapid testing, structural auditing, and development. |
## 📥 Section 1: Installation & Deployment
Hyperion requires **Python 3.9** or later.
### 1. Install System Dependencies
The core component liboqs-python compiles native C bindings from the *Open Quantum Safe* project. You must configure your environment with compilation tools before fetching requirements.
 * **Ubuntu / Debian / Linux VPS:**
```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake libssl-dev git tor

```
 * **Android Termux:**
```bash
pkg update && pkg upgrade -y
pkg install build-essential cmake openssl git tor python -y

```
### 2. Clone Repository and Install Packages
```bash
# Clone the project code
git clone https://github.com/reyzzzl/Hyperion-CLI.git
cd Hyperion-Chat

# Install Python module dependencies
pip install liboqs-python cryptography pysocks stem argon2-cffi

# Build and register the package globally
pip install .

```
*(Note: Compiling liboqs-python can take roughly 3–5 minutes as it compiles native cryptographic structures from source).*
### 3. Verify Installation Integrity
Confirm all post-quantum wrappers and cryptographic modules have integrated correctly into your machine:
```bash
python3 -c "
from hyperion.core.pqc import PQC_AVAILABLE
from hyperion.core.ratchet import DoubleRatchet
from hyperion.core.identity import SecureIdentity
print('PQC Kyber-512 Status:', PQC_AVAILABLE)
print('System Modules Status: OK')
"

```
**Expected Terminal Output:**
```text
PQC Kyber-512 Status: True
System Modules Status: OK

```
## 🔑 Section 2: Setup Cryptographic Identity (First Run)
When launching Hyperion for the first time, you must provision security access passphrases. These passes wrap your long-term Ed25519 profile signatures and local SQLite rows at rest:
```bash
python3 main.py host

```
**Interactive Configuration Prompt Sequence:**
```text
Set password for identity storage: [Type master password - characters hidden]
Confirm password:                  [Retype master password]
Set storage password:              [Type local message database encryption passphrase]

```
> ⚠️ **CRITICAL WARNING:** There is no back-door or recovery mechanism for these passphrases. If lost, your databases will remain permanently bricked.
>  * Private profiles partition localized states inside ~/.hyperion/hyperion_identity.json.
> 
## 📡 Section 3: Operational Connectivity Guides
Hyperion supports two core connection methods out of the box: Local Mode (for testing on the same machine/network) and Tor Onion Mode (for decentralized, anonymous wide-area connections).
### Method A: Local Host Loop-back Testing (Single Machine, Dual Tabs)
The fastest approach to verify code execution without relying on live external networks:
 * **Terminal Tab 1 — Local Server Listener Host:**
```bash
python3 main.py host

```
*Expected Display Response:*
```text
[LOG] [+] PQC Kyber-512 available
Enter identity password: [Type your password]
[*] Starting Kyber-512 PQC server...
[LOG] [*] Generating Kyber-512 keys...
[LOG] [*] Identity: [Your-16-Character-Hex-ID]
[LOG] [!] Tor not available, using local mode
[+] Your address: 127.0.0.1:9999
[*] Share this with your peer
[*] Waiting for connection...

```
*Note down the local listener address parameter generated (e.g., 127.0.0.1:9999).*
 * **Terminal Tab 2 — Client Connection Instance:**
```bash
python3 main.py connect 127.0.0.1:9999

```
*Expected Display Response:*
```text
[LOG] [+] PQC Kyber-512 available
Enter identity password: [Type your password]
[LOG] [*] Connecting to 127.0.0.1:9999...
[LOG] [+] Connected directly
[LOG] [*] PQC handshake in progress...
[LOG] [+] Peer verified: [Remote-16-Character-Hex-ID]
[LOG] [+] Secure channel established
[+] Connected! Secure channel established.
[*] Entering chat mode. Type '/help' for commands.

[YOU] 

```
### Method B: Anonymized Onion Routing Mode (Live Tor Circuit)
For maximum production-grade operational protection across VPS or mobile Termux systems, interact across native hidden service lines.
 1. Turn on and bootstrap your background Tor routing engine interface:
```bash
tor --ControlPort 9051 --SOCKSPort 9050 &

```
*Wait for the internal stream log to push past setup constraints:* Bootstrapped 100% (done).
 2. **Spin up onion host parameters:**
```bash
python3 main.py host

```
The client triggers structural rules via the stem engine controller, talks to your local Tor daemon, registers an ephemeral hidden site, and returns a .onion configuration string address to share:
```text
[+] Your address: abc123xyz456example.onion

```
 3. **Establish Client Peer Link:** Ensure the connecting peer also has an active Tor daemon listening locally, then bridge directly using the .onion address:
```bash
python3 main.py connect abc123xyz456example.onion

```
## 🛠️ Section 4: Chat Shell Control Directives
Once a secure handshake drops you into the live conversational loop, raw strings passed into the entry prompt are automatically wrapped inside the active ratchet and dispatched. Input sequences prefixed with a forward slash (/) trigger operational system modules:
| Terminal Command | Action Description |
|---|---|
| /help | Renders the inline interactive usage and features manual. |
| /fingerprint | Prints local and remote Ed25519 identity verification hash strings. |
| /rekey | Instantly forces an explicit rotation step across the main root key arrays. |
| /history [limit] | Extracts and decrypts database message records up to the specified row limit (e.g., /history 20). |
| /contacts | Pulls out saved contact address rows, aliases, and trust markers. |
| /trust <address> | Marks an entry address as an explicitly trusted node in your data tables. |
| /alias <address> <name> | Binds a recognizable descriptive text tag to a complex connection address string. |
| /sessions | Lists all structural background session profiles stored in cache. |
| /switch <address> | Hot-swaps the current chat frame focus over to a different tracked session state. |
| /send-file <path> | Segments, delete keys, encrypts, and pipes target files across the ratchet into the peer's directory. |
| /status | Outputs sessional diagnostic status vectors, metrics, and indicators. |
| /panic | Instantly executes a memory wipe array, kills background threads, purges SQLite databases, and drops the process. |
| /quit or /exit | Gracefully drops active socket lanes and returns you to standard system shell configurations. |
> 🔒 **Mandatory Operational Security Task:** After establishing a secure session link, always execute /fingerprint. Compare the 16-character string printed for your peer via an independent **Out-of-Band Channel** (such as a voice call or physical reading) to verify the line is clean and completely immune to active interception attempts.
> 
## 🔒 Storage Architecture & Threat Model
### Local Footprint Layout
Hyperion segregates components on disk to enforce strict cryptographic boundaries:
 * hyperion_messages.db ──> Protected via hybrid **AES-256-GCM** encryption.
 * hyperion_sessions.db ──> Plaintext SQLite (stores non-sensitive operational metadata only).
 * hyperion_identity.json ──> Hardened via **Scrypt + AES-256-GCM** wrappers.
### Emergency Panic Button
Executing /panic triggers a complete zeroization protocol:
```text
/panic ──> Secure memory scrub (RAM keys wiped) ──> Disk database scrubbing (Shreds keys) ──> Hard Exit

```
*Once executed, no recoverable cryptographic sessional data or private master identity states remain on the hardware platform.*
## 📊 Feature Comparison Matrix
| Application Feature | Signal Messenger | WhatsApp | Telegram | Hyperion PQC v2.0.0 |
|---|---|---|---|---|
| **Post-Quantum Crypto** | ❌ Classical | ❌ Classical | ❌ Classical | ✅ **Kyber-512 + Dilithium5** |
| **Multi-Session View** | ✅ Yes | ✅ Yes | ✅ Yes | ✅ **Yes** |
| **Offline Messaging Queue** | ✅ Yes | ✅ Yes | ✅ Yes | ✅ **Yes** |
| **Encrypted Database History** | ✅ Yes | ✅ Yes | ❌ No | ✅ **Yes (AES-256-GCM Layer)** |
| **Native Storage Panic Button** | ❌ No | ❌ No | ❌ No | ✅ **Yes (Memory + Disk Wipe)** |
## 🧹 Section 5: Factory Reset & Clean Purge
To completely wipe all metadata history logs, clear active contact tables, zeroize identity parameter stores, and return the application workspace environment to a factory-blank status:
```bash
# Erase user profile hidden configuration cache directories
rm -rf ~/.hyperion/

# Wipe databases, salt containers, and identities from the active source directory
rm -f hyperion_*.db hyperion_*.salt hyperion_identity.json

```
## 📊 Summary of Absolute Quick-Start Commands
```bash
# Build (Run once)
sudo apt install build-essential cmake libssl-dev tor -y
pip install liboqs-python cryptography pysocks stem argon2-cffi
git clone [https://github.com/reyzzzl/Hyperion-Chat.git](https://github.com/reyzzzl/Hyperion-Chat.git)
cd Hyperion-Chat && pip install .

# Launch Listener Node
python3 main.py host

# Launch Link Operator
python3 main.py connect <target_address_or_onion_string>

# Sudden Wiped Emergency Kill
python3 main.py panic

```
## 📚 References & Further Reading

These resources serve as the architectural foundation for Hyperion:

* [NIST FIPS 203 — ML-KEM Standard](https://csrc.nist.gov/pubs/fips/203/ipd)
* [Open Quantum Safe (OQS) Project](https://openquantumsafe.org/)
* [The Signal Protocol Specifications](https://signal.org/docs/)
* [RFC 5869 — HKDF Specification](https://datatracker.ietf.org/doc/html/rfc5869)
* [The Tor Project Documentation](https://community.torproject.org/onion-services/)
* [A Graduate Course in Applied Cryptography](https://toc.cryptobook.us/)
## 📝 License
Distributed under the **GNU General Public License v3.0**. Review the LICENSE container text block file for complete operational distribution and compilation rules.