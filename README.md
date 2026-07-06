# Hyperion PQC


![Status Version](https://img.shields.io/badge/Status-V1-red.svg)
![Type CLI--Application](https://img.shields.io/badge/Type-CLI%20Application-blue.svg)
![Crypto Kyber--512%20%7C%20ML--KEM](https://img.shields.io/badge/Crypto-Kyber--1024%20%7C%20ML--KEM-orange)
![Network Tor%20Onion%20Routing](https://img.shields.io/badge/Network-Tor%20Onion%20Routing-purple)
![languange](https://img.shields.io/badge/Lang-Rust-cream)

**Post-Quantum Encrypted Messenger — CLI-based, Tor-enabled, Quantum-Resistant**

## what is This?

hyperion is a terminal-based messenger that is end-to-end encrypted with post-quantum cryptography
Hyperion v2.0.0 has been completely overhauled into a fully modular Python package featuring an interactive cli terminal interface, encrypted local persistent databases, offline message queues, and a multi-factor key derivation architecture.

## Concept
the encryption used in ordinary messengers now often includes RSA, ECDH, etc, ofc if we look at the development of computers in the future, it is very possible that these algorithms will be broken. hyperion is designed to be resistant to quantum computer attacks that use standard post-quantum cryptography nist. namely kyber and dilithium

### Cryptographic stack
- key Exchange:Kyber1024 (post-quantum KEM)
- signatures: Dilithium5 (post-quantum digital signatures)
- sncryption: XChaCha20-Poly1305 (AEAD)
- key Derivation: argon2id (password-based) + HKDF
- forward Secrecy: double ratchet (signal-style per-message keys)
-  anonymity (optional): tor support via SOCKS proxy

## build architecture 
| OS | Target triple | Binary |
|---|---|---|
| Linux | x86_64-unknown-linux-gnu | hyperion-linux |
| Windows | x86_64-pc-windows-msvc | hyperion-windows.exe |
| macOS | x86_64-apple-darwin | hyperion-macos |
> for mac is architecture for intel, not apple silicon. thic can run if past rosetta 2( native ARM run in the next update)

## Installation

download the latest binary for your platform from [Releases](https://github.com/reyzzzl/Hyperion-CLI/releases/latest).

### linux
```
curl -L -o hyperion https://github.com/reyzzzl/Hyperion-CLI/releases/latest/download/hyperion-linux
chmod +x hyperion
```

### macos
```
curl -L -o hyperion https://github.com/reyzzzl/Hyperion-CLI/releases/latest/download/hyperion-macos
chmod +x hyperion
xattr -d com.apple.quarantine hyperion
```

### windows 
```
Invoke-WebRequest -Uri "https://github.com/reyzzzl/Hyperion-CLI/releases/latest/download/hyperion-windows.exe" -OutFile "hyperion.exe"
```

## Usage
```
hyperion --password <PASSWORD> init
hyperion --password <PASSWORD> host --port <PORT>
hyperion --password <PASSWORD> connect --host <HOST> --port <PORT>
```
   
## next update 
- add emphadd emeral key or 2 client
- fix some bug
- add some features 
- focus on tor development 
- improve architecture better 
- add ARM support for macos