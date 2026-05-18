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
## 💻 Technical Command Matrix
Hyperion operates entirely via a responsive command-line interface. While inside an active shell session, input strings prefixed with a forward slash (/) trigger administrative modules:
 * /sessions - Inspect all tracked sessional structures cached on disk.
 * /switch <address> - Hot-swap the current input display focus to a different peer address.
 * /contacts - Pull up the contact database showing aliases and verified trust signatures.
 * /alias <address> <name> - Assign a human-readable name string to a complex network address target.
 * /trust <address> - Manually sign a peer contact as an explicitly trusted node.
 * /history [limit] - Decrypt and output stored database message records up to a specific row constraint.
 * /send-file <path> - Chunks, encrypts, and pipes files across the active PQC channel.
 * /panic - Immediate emergency self-destruct command.
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
## 📥 Installation & Build Deployment
You'll need **Python 3.9** or later.
### 1. Install System Dependencies
The underlying liboqs-python framework links directly to native binaries from the *Open Quantum Safe* infrastructure. Set up your compiler dependencies:
 * **Ubuntu/Debian:**
```bash
sudo apt install build-essential cmake tor

```
### 2. Package Compilation via PIP
Since Hyperion v2.0.0 is built around a standardized setup.py format, you can compile and distribute the global binary path hyperion across your system paths instantly:
```bash
git clone [https://github.com/reyzzzl/Hyperion-CLI.git](https://github.com/reyzzzl/Hyperion-CLI.git)
cd Hyperion-Chat
pip install .

```
### 3. Execution Infrastructure
Once installed, launch node scripts globally from any terminal directory path:
 * **To host a secure network lane:**
```bash
hyperion host

```
 * **To bridge an active route to an operating host:**
```bash
hyperion connect <peer_address_or_onion_string>

```
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

* [NIST FIPS 203 — ML-KEM Standard](https://csrc.nist.gov/pubs/fips/203/ipd)
* [Open Quantum Safe (OQS) Project](https://openquantumsafe.org/)
* [The Signal Protocol Specifications](https://signal.org/docs/)
* [RFC 5869 — HKDF Specification](https://datatracker.ietf.org/doc/html/rfc5869)
* [The Tor Project Documentation](https://community.torproject.org/onion-services/)
* [A Graduate Course in Applied Cryptography](https://toc.cryptobook.us/)
## 📝 License
Distributed under the **GNU General Public License v3.0**. See LICENSE for the full text. You can copy, modify, and distribute this software, provided you keep it open-source under the same license.