# Hyperion PQC

![Status Version](https://img.shields.io/badge/Status-V2-red.svg)
![Type CLI--Application](https://img.shields.io/badge/Type-CLI%20Application-blue.svg)
![Crypto Kyber--512%20%7C%20ML--KEM](https://img.shields.io/badge/Crypto-Kyber--512%20%7C%20ML--KEM-orange)
![Network Tor%20Onion%20Routing](https://img.shields.io/badge/Network-Tor%20Onion%20Routing-purple)
![Python Version](https://img.shields.io/badge/Python-3.9+-blue)

**Post-Quantum Encrypted Messenger — CLI-based, Tor-enabled, Quantum-Resistant**

---

> "Privacy is not about having something to hide. It's about having something to protect."

## 📌 What is This?

**Hyperion** is a peer-to-peer encrypted messenger built around one idea: *your conversations belong to you, and only you.* It uses **post-quantum cryptography** — the kind that stays secure even against future quantum computers — combined with **onion routing via Tor** to give you a private channel that's both technically strong and philosophically honest.

Hyperion v2.0.0 has been completely overhauled into a fully modular Python package featuring an interactive CLI terminal interface, encrypted local persistent databases, offline message queues, and a multi-factor key derivation architecture.

Everything here is open source under **GPL-3.0**. You can read it, run it, audit it, fork it, break it, and improve it.

---

## ⚡ v2.0.0 New Features & Innovations

### 1. Complete Post-Quantum Cryptography (PQC) Stack
Hyperion utilizes a dual-layer quantum security ecosystem via `liboqs` to resist both classical attacks and future quantum decryption vectors (Shor's and Grover's algorithms).

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
## 🛠️ Cryptographic Stack & Security Notes
| Primitive / Protocol | Role | Details & Context |
|---|---|---|
| **CRYSTALS-Kyber (Kyber-512)** | Key Encapsulation (KEM) | Based on Module Learning With Errors (MLWE). Standardized as **FIPS 203**. Implemented via liboqs. |
| **Double Ratchet** | Symmetric Key Management | Inspired by Signal Protocol. Hashes chain keys forward with SHA3-256 after every message to prevent backward reconstruction. |
| **AES-256-GCM** | Authenticated Encryption | Provides confidentiality and integrity. The authentication tag is verified *before* decryption to prevent tampering. |
| **Ed25519** | Identity Signatures | Signs the handshake payload to prevent Man-in-the-Middle (MitM) attacks. Fast, compact, and trusted. |
| **MultiKDF (Argon2 / Scrypt / PBKDF2)** | Master Key Derivation | Cascades three hardened functions via XOR mapping (Argon2id ^ Scrypt ^ PBKDF2) to encrypt database headers at rest. |
| **SQLite3 (AES-256-GCM Layer)** | Encrypted Local Storage | Encrypts rows for transaction history (hyperion_messages.db) and sessions (hyperion_sessions.db) on disk. |
 * All messages are end-to-end encrypted with **AES-256-GCM**.
 * Perfect Forward Secrecy is strictly enforced via the **Double Ratchet** algorithm.
 * Identity keys are stored encrypted with **Scrypt + AES-256-GCM** wrappers.
 * The panic button instantly overwrites keys in RAM and shreds local databases on disk.
 * **No central servers** – pure peer-to-peer deployment via Tor or direct loop-back IP.
## 💻 Supported Environments
 * **VPS (Ubuntu/Debian):** Recommended deployment target. Supports background Tor services natively.
 * **Termux (Android):** No root required. Fully functional post-quantum terminal environment.
 * **Local Linux / macOS / Windows (WSL):** Ideal environment for rapid testing, structural auditing, and development.
## 📥 Installation & Deployment
### 1. Native Build from Source
You'll need **Python 3.9** or later.
```
sudo apt update && sudo apt install -y build-essential cmake libssl-dev git tor python3 python3-pip

```
### Clone this repo
```bash
git clone https://github.com/reyzzzl/Hyperion-CLI.git

```
```bash
cd Hyperion-CLI

```
### Install requirements library
```bash
pip install -r requirements.txt

```
### install hyperion 
```bash
pip install .

```
*(Note: Compiling liboqs-python can take roughly 3–5 minutes as it compiles native cryptographic structures from source).*
### 2. Deployment via Docker (Recommended)
```bash
docker build -t hyperion:latest .

```
### Create host docker
```bash
docker run -it --rm -p 9999:9999 hyperion:latest host

```
### Connect docker to client
```bash
docker run -it --rm hyperion:latest connect 127.0.0.1:9999

```
### Clean docker client
```bash
docker run -it --rm --network host hyperion:latest host

```
## 🔑 Setup Cryptographic Identity (First Run)
When launching Hyperion for the first time, you will be prompted to set up two master passwords via terminal prompts:
```bash
python main.py host

```
 1. **Identity Password:** Protects your Ed25519 private key profile (saved inside ~/.hyperion/hyperion_identity.json).
 2. **Storage Password:** Generates the cryptographic MultiKDF barrier to lock your message history database rows at rest.
> Save these passwords securely. There is no back-door, recovery mechanism, or password reset function by design. If lost, your databases will remain permanently bricked.
> 
## 📡 Operational Connection Examples
### Method A: Local Host Loop-back Testing (Dual Terminal Instances)
 * **Terminal 1 – Host Node:**
```bash
python main.py host

```
 * **Terminal 2 – Client Link:**
```bash
python main.py connect 127.0.0.1:9999

```
### Method B: Anonymous Communication via Tor Hidden Circuits
 * **Terminal 1 – Hidden Service Host (Run Tor first, then Host):**
```bash
tor --ControlPort 9051 --SOCKSPort 9050 &

```
```bash
python main.py host

```
*Share the ephemeral .onion address shown on the viewport.*
 * **Terminal 2 – Client Connection Instance (Run Tor first, then Connect):**
```bash
tor --ControlPort 9051 --SOCKSPort 9050 &

```
```bash
python main.py connect xyz123abc456example.onion

```
## 🛠️ Chat Shell Control Directives
Once a secure handshake drops you into the live conversational loop, raw strings passed into the entry prompt are automatically wrapped inside the active ratchet and dispatched. Input sequences prefixed with a forward slash (/) trigger operational system modules:
| Terminal Command | Action Description |
|---|---|
| /sessions | Inspect all tracked sessional structures cached on disk. |
| /switch <address> | Hot-swap the current input display focus to a different peer address. |
| /contacts | Pull up the contact database showing aliases and verified trust signatures. |
| /alias <address> <name> | Assign a human-readable name string to a complex network address target. |
| /trust <address> | Manually sign a peer contact as an explicitly trusted node. |
| /history [n] | Decrypt and output stored database message records up to n rows (Default: 50). |
| /send-file <path> | Chunks, encrypts, and pipes target files across the active PQC channel. |
| /fingerprint | Prints local and remote Ed25519 identity verification hash strings. |
| /rekey | Instantly forces an explicit rotation step across the main root key arrays. |
| /panic | Emergency wipe — delete all cryptographic keys, databases, and drop the application. |
| /quit or /exit | Gracefully drops active socket lanes and exits the application window. |
### Send a file
```bash
/send-file /path/to/document.pdf

```
### Emergency wipe
```bash
/panic

```
*Type 'WIPE' to confirm.*
> 🔒 **Mandatory Operational Security Task:** After establishing a secure session link, always execute /fingerprint. Compare the 16-character string printed for your peer via an independent **Out-of-Band Channel** (such as a voice call or physical reading) to verify the line is clean and completely immune to active interception attempts.
## 🛑 Known Limitations
 * **File Transfer Thresholds:** File transmission operates over fixed 512 KB chunk segments.
 * **Payload Constraints:** Maximum hardcoded packet message buffer boundary is set to 50 MB.
 * **Tor Propagation Latency:** Ephemeral hidden service generation hooks take roughly 5–10 seconds to publish to the Tor network circuit.
 * **Build Compilation Requirements:** First run requires a global C-compiler setup to build the native liboqs footprint wrapper (takes 3–5 minutes).
## 📊 Feature Comparison Matrix
| Application Feature | Signal Messenger | WhatsApp | Telegram | Hyperion PQC v2.0.0 |
|---|---|---|---|---|
| **Post-Quantum Crypto** | ❌ Classical | ❌ Classical | ❌ Classical | ✅ **Kyber-512 + Dilithium5** |
| **Multi-Session View** | ✅ Yes | ✅ Yes | ✅ Yes | ✅ **Yes** |
| **Offline Messaging Queue** | ✅ Yes | ✅ Yes | ✅ Yes | ✅ **Yes** |
| **Encrypted Database History** | ✅ Yes | ✅ Yes | ❌ No | ✅ **Yes (AES-256-GCM Layer)** |
| **Native Storage Panic Button** | ❌ No | ❌ No | ❌ No | ✅ **Yes (Memory + Disk Wipe)** |
## 🔍 Troubleshooting
 * **"Connection refused"** ──> Ensure the host node instance is currently active, listening, and your network interface binding address parameters are typed correctly.
 * **"Peer verification failed"** ──> Potential active Man-in-the-Middle (MITM) hijacking attempt detected. Drop the circuit immediately and verify the identity fingerprints over an out-of-band communication channel.
 * **"liboqs not found"** ──> The Python binding failed to link to native workspace components. Execute pip install liboqs-python manually or wait for the compiler to complete tracking operations.
 * **Messages not sending / State Desync** ──> Clear local runtime tracking footprints entirely and restart the node loops across both communication endpoints:
```bash
rm -rf ~/.hyperion/

```
## 📚 References & Further Reading

These resources serve as the architectural foundation for Hyperion:

* [NIST FIPS 203 — ML-KEM Standard](https://csrc.nist.gov/pubs/fips/203/ipd)
* [Open Quantum Safe (OQS) Project](https://openquantumsafe.org/)
* [The Signal Protocol Specifications](https://signal.org/docs/)
* [RFC 5869 — HKDF Specification](https://datatracker.ietf.org/doc/html/rfc5869)
* [The Tor Project Documentation](https://community.torproject.org/onion-services/)
* [A Graduate Course in Applied Cryptography](https://toc.cryptobook.us/)
## 🤝 Contributing & Bug Reports
Issues and pull requests are highly welcome. If you catch a functional bug, a visual glitch, or a deep architectural flaw, please open a detailed diagnostic ticket via **GitHub Issues**.
## 📝 License
Distributed under the **GNU General Public License v3.0**. Review the LICENSE container text block file for complete operational distribution and compilation rules.