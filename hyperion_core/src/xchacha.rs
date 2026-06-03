// SPDX-License-Identifier: GPL-3.0
use xchacha20poly1305::{XChaCha20Poly1305, Key, Nonce};
use xchacha20poly1305::aead::{Aead, KeyInit};
use rand::RngCore;

pub const NONCE_SIZE: usize = 24;

pub fn xenc(key: &[u8; 32], plain: &[u8], aad: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let ciphertext = cipher.encrypt(nonce, plain, aad).unwrap();
    (nonce_bytes.to_vec(), ciphertext)
}

pub fn xdec(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let nonce = Nonce::from_slice(nonce);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher.decrypt(nonce, ciphertext, aad).map_err(|_| "Decryption failed".into())
}