// SPDX-License-Identifier: GPL-3.0
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HyperionError {
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid handshake message")]
    InvalidHandshake,
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Unknown version: {0}")]
    UnknownVersion(u8),
}