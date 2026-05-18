# Hyperion PQC

![Status Beta](https://img.shields.io/badge/Status-Beta-red.svg)
![Type CLI--Application](https://img.shields.io/badge/Type-CLI%20Application-blue.svg)
![Crypto Kyber--512%20%7C%20ML--KEM](https://img.shields.io/badge/Crypto-Kyber--512%20%7C%20ML--KEM-orange)
![Network Tor%20Onion%20Routing](https://img.shields.io/badge/Network-Tor%20Onion%20Routing-purple)
![Python Version](https://img.shields.io/badge/Python-3.9+-blue)

**Post-Quantum Encrypted Messenger — Built for the Open Internet**

---

> "Privacy is not about having something to hide. It's about having something to protect."

## 📌 What is This?

**Hyperion** is a peer-to-peer encrypted messenger built around one idea: *your conversations belong to you, and only you.* It uses **post-quantum cryptography** — the kind that stays secure even against future quantum computers — combined with **onion routing via Tor** to give you a private channel that's both technically strong and philosophically honest.

Hyperion v2.0.0 has been refactored into a fully modular, production-grade Python package with an interactive, rich ANSI-colored CLI terminal interface, encrypted local persistent databases, and automatic background key rotations.

Everything here is open source under **GPL-3.0**. You can read it, run it, audit it, fork it, break it, and improve it.

## ⚖️ Why Does This Exist?

The internet promised open communication. What we got instead is platforms that log everything, governments that can compel disclosure, and infrastructure built on cryptography that quantum computers will eventually break. 

This project is a small answer to that problem. Not the only answer, and not a perfect one — but an honest one. The cryptographic primitives used here (`Kyber-512`, `Ed25519`, `AES-256-GCM`, `Double Ratchet`) are the same building blocks that serious security researchers use. The goal is to make them accessible, auditable, and free.

---

## 🚀 Features

* **Advanced CLI Terminal Interface:** An interactive text dashboard rendering ANSI color blocks, isolated sessional layouts, and background socket handling loops.
* **Persistent Multi-Session Management:** Background SQLite handling via `SessionManager` which maintains separate chat states and structures for multiple peers simultaneously.
* **Hybrid Storage Key Derivation (MultiKDF):** Protects identity structures and local databases using an interleaved XOR combination of **Argon2id**, **Scrypt**, and **PBKDF2-HMAC-SHA512** to resist elite hardware brute-force matrices.
* **Kyber-512 Post-Quantum Key Exchange:** Standardized as *ML-KEM* by NIST (FIPS 203), protecting handshakes against future quantum computing retro-active decryption attacks.
* **Double Ratchet with Perfect Forward Secrecy:** Continuous message-key step progression combined with an asynchronous message queue system for offline or delayed delivery.
* **Automated Background Rekeying:** Triggers structural key updates automatically every 100 messages or 10 minutes to strictly isolate prolonged sessional transactions.
* **Tor Hidden Service Integration:** Native programmatic compilation of ephemeral Tor `.onion` routing lines via the `stem` controller framework.

---

## 🛠️ Cryptographic Stack

Understanding what's protecting you matters. Here's the full stack and why each piece was chosen:

| Primitive / Protocol | Role | Details & Context |
| :--- | :--- | :--- |
| **CRYSTALS-Kyber (Kyber-512)** | Key Encapsulation (KEM) | Based on Module Learning With Errors (MLWE). Standardized as **FIPS 203**. Implemented via `liboqs`. |
| **Double Ratchet** | Symmetric Key Management | Inspired by Signal Protocol. Hashes chain keys forward with SHA3-256 after every message to prevent backward reconstruction. |
| **AES-256-GCM** | Authenticated Encryption | Provides confidentiality and integrity. The authentication tag is verified *before* decryption to prevent tampering. |
| **Ed25519** | Identity Signatures | Signs the handshake payload to prevent Man-in-the-Middle (MitM) attacks. Fast, compact, and trusted. |
| **MultiKDF (Argon2 / Scrypt / PBKDF2)** | Master Key Derivation | Cascades three hardened functions via XOR mapping (`Argon2id ^ Scrypt ^ PBKDF2`) to encrypt database headers at rest. |
| **SQLite3 (AES-256-GCM Layer)** | Encrypted Local Storage | Encrypts rows for transaction history (`hyperion_messages.db`) and sessions (`hyperion_sessions.db`) on disk. |

---

## 📥 Installation

You'll need **Python 3.9** or later.

### 1. Install System Dependencies
The critical dependency is `liboqs-python`, which wraps the native C library from the *Open Quantum Safe* project. Depending on your platform, you may need a build environment:

* **Ubuntu/Debian:**
```bash
sudo apt install build-essential cmake tor

```
### 2. Clone and Install the Package via PIP
Since Hyperion is fully packaged using setup.py, you can install it globally or within a virtual environment to register the command-line binary tool hyperion across your system terminal paths:
```bash
git clone [https://github.com/reyzzzl/Hyperion-Chat.git](https://github.com/reyzzzl/Hyperion-Chat.git)
cd Hyperion-Chat

# Install package dependencies and binary configurations
pip install .

```
### 3. Tor Configuration (Optional for Onion Mode)
For Tor support, ensure Tor is running locally on your machine with the control port enabled:
```bash
tor --ControlPort 9051

```
*The stem controller framework inside Hyperion will automatically query communication interfaces on ports 9051 or 9151 to host services.*
## 💻 How to Use (Step-by-Step CLI Guide)
Hyperion operates entirely via automated terminal console loops.
### 1. Launching and Unlocking Identities
Upon initial package entry compilation, execution flags dictate operational behavior:
 * **To Start Server/Host Mode:**
```bash
hyperion host

```
 * **To Connect to a Peer Node:**
```bash
hyperion connect <peer_address_or_onion>

```
 * **Security Key Isolation:** On the very first run, you will be prompted to set a master storage password to encrypt local data tables. On subsequent executions, entering the passphrase unlocks your cryptographic **Fingerprint ID** signature profile. You have exactly **3 entry attempts** before safety checks drop active loops and trigger an application exit lock.
### 2. Establishing the Network Connection
 * **Host Mode Pipeline:** Executing hyperion host prompts the terminal to construct ephemeral post-quantum structures and connect to Tor background relays. If successful, your unique .onion line outputs to the screen. If Tor is absent, the engine falls back to local routing mode and displays an active socket address (e.g., 192.168.1.5:9999). Copy and send this connection token to your peer.
 * **Connecting Peer Pipeline:** Executing hyperion connect <address> launches a socket connection script to link up with the active host node.
 * **Handshake Completion:** The protocol handles key compilation asynchronously. Once completed, both text inputs unlock, and the shell console returns SECURE CHANNEL ESTABLISHED.
### 3. Identity Verification (Mandatory Audit)
To structurally guarantee that an unauthorized network agent is not running a traffic proxy configuration (**Man-in-the-Middle Attack**), execute this check immediately after a successful link:
 1. Type /fingerprint inside the active chat input bar and hit **Enter**.
 2. The interactive layout prints out your local configuration fingerprint hash sequence right above the verification fingerprint captured from the connected peer.
 3. Compare these token positions with the other side through an alternate **Out-of-Band Channel** (e.g., an encrypted voice line or physical reading). If matching positions are true, your line is cryptographically validated.
### 4. Terminal Command Matrix
While inside the active communication room loop, the message line field parses control commands prefixed with a forward slash (/):
| Terminal Command | Action Description |
|---|---|
| /help | Renders the full interactive inline help manual. |
| /fingerprint | Prints local and remote Ed25519 identity verification hash strings. |
| /rekey | Instantly forces an explicit rotation step across the main root key arrays. |
| /history [limit] | Extracts and decrypts database message records up to the specified row limit. |
| /contacts | Pulls out saved contact address rows, aliases, and trust markers. |
| /trust <address> | Marks an entry address as an explicitly trusted node in your data tables. |
| /alias <address> <name> | Binds a recognizable descriptive text tag to a complex connection address string. |
| /sessions | Lists all structural background session profiles stored in cache. |
| /switch <address> | Hot-swaps the current chat frame focus over to a different tracked session state. |
| /send-file <path> | Segments, encrypts, and pipes target files across the ratchet into the peer's directory. |
| /panic | Instantly executes a memory wipe array, kills background threads, purges SQLite databases, and drops the process. |
| /quit or /exit | Gracefully drops active socket lanes and returns you to standard system shell configurations. |
## 🛑 Important Limitations
Before expecting a commercial user experience like WhatsApp or Signal, please review these specific research-oriented design boundaries:
 * **Terminal-Locked Input:** This package relies on terminal standard input streams. Sessional hot-swaps and multi-session routing logic are complete, but notifications for inactive sessions remain silent until the target view focus is switched manually via /switch.
 * **Database Dependency:** If local database files (hyperion_messages.db or hyperion_sessions.db) are deleted or modified externally without matching configuration passphrases, the local storage breaks integrity constraints and forces a sessional reset.
## 🛡️ Threat Model
Hyperion is honest about what it does and does not protect against.
### What is Protected:
 * **Passive Network Surveillance:** Adversaries capturing raw network packets cannot read the encrypted contents.
 * **IP Address Correlation:** Passing data through Tor hidden circuits masks the true IP addresses of both hosts from each other and outsiders.
 * **Future Quantum Attacks:** Intercepted session data remains secure against retro-active quantum decryption due to the underlying Kyber-512 architecture.
 * **Past Session Compromise:** *Perfect Forward Secrecy* prevents an adversary from decrypting past logged chats even if current sessional keys are leaked later.
### What is NOT Protected:
 * **Endpoint Compromise:** An operating system or kernel that has already been infected with an active infostealer or malware payload.
 * **Advanced Metadata Analysis:** High-level timing analysis, message frequency mapping, and connection duration modeling.
 * **Unverified Fingerprints:** Skipping manual fingerprint verification leaves the session open to active Man-in-the-Middle key-swapping schemes.
 * **Memory Forensics:** Python does not natively guarantee immediate *RAM scrubbing*. The panic button makes a best-effort attempt to clear runtime arrays, but artifacts might still be retrievable via forensic hardware extraction immediately after termination.
> ⚠️ **Tor Caveat:** Global adversaries capable of observing both ends of a Tor circuit can potentially map traffic profiles using timing correlations. For nation-state level threats, software alone is never a standalone solution.
> 
## 🚨 Disclaimer & Project Status
> ⚠️ **CRITICAL:** The Hyperion project is currently in its **Beta Phase** and is strictly meant for research and educational purposes. The codebase **has not been audited by an independent, professional third-party firm**.
> 
Cryptographic engineering is highly fragile—the minor misconfiguration of an implementation vector can break theoretical safety. Do not rely on this project as your primary means of defense if your life, safety, or high-risk operational security depends on it. If you are in a vulnerable situation, utilize battle-tested tools and consult trusted frameworks like the EFF's Surveillance Self-Defense Guide.
### 🐛 Bug Reporting & Feedback
We actively look for code reviews, feedback, and structural critiques from peer developers and security researchers to refine the implementation. If you catch a bug, structural glitch, or a technical flaw:
 * **Functional/UI Bugs:** Please open a new *Issue* in this repository outlining the detailed steps to reproduce, environmental logs, and error traces so we can isolate the bug.
 * **Cryptographic Vulnerabilities:** If you discover a theoretical flaw or implementation issue regarding the math/crypto layers, please initiate an open discussion thread within the *Issues* tab first so it can be publicly vetted before submitting a *Pull Request*.
## 🤝 Contributing
Contributions are highly welcome. High-priority improvement paths currently include:
 * Completing a full *Diffie-Hellman ratchet* implementation to allow post-compromise break-in recovery.
 * Migrating data packets from basic string delimiters (||END||) to a structured *binary framing protocol*.
 * Porting core application structures to mobile ecosystems (Android/iOS).
## 📚 References & Further Reading
These resources serve as the architectural foundation for Hyperion:
 * NIST FIPS 203 — ML-KEM Standard
 * Open Quantum Safe (OQS) Project
 * The Signal Protocol Specifications
 * RFC 5869 — HKDF Specification
 * The Tor Project Documentation
 * A Graduate Course in Applied Cryptography
## 📝 License
Distributed under the **GNU General Public License v3.0**. See LICENSE for the full text. You can copy, modify, and distribute this software, provided you keep it open-source under the same license.
# Hyperion-CLI