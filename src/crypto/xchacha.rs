use chacha20poly1305::{XChaCha20Poly1305, Key, Nonce};
// fix previous import in XChaCha20Poly1305 
use anyhow::Result;

pub fn encrypt(key: &[u8; 32], nonce: &[u8; 24], data: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    cipher.encrypt(nonce, data).map_err(Into::into)
}

pub fn decrypt(key: &[u8; 32], nonce: &[u8; 24], data: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    cipher.decrypt(nonce, data).map_err(Into::into)
}
// TODO: use ZeroizeOnDrop or reference key is  clean after use 
// tbh i want to use, ZeroizeOnDrop in dilithium. is minimally security bt good enough for just hackclub demo 