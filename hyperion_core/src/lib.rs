// SPDX-License-Identifier: GPL-3.0

pub mod kyber;
pub mod dilithium;
pub mod kdf;
pub mod xchacha;
pub mod ratchet;
pub mod protocol;
pub mod error;

pub use kyber::{Kyber, SecretKey as KyberSecretKey, KyberKeypair};
pub use dilithium::{Dilithium, SecretKey as DilithiumSecretKey, DilithiumKeypair};
pub use kdf::{derive_key, hkdf, SALT_SIZE, KEY_LEN};
pub use xchacha::{xenc, xdec, NONCE_SIZE};
pub use ratchet::{Ratchet, RatchetState, MAX_SEQ_WINDOW};
pub use protocol::{HandshakeMessage, ServerResponse};
pub use error::HyperionError;