use xchacha20poly1305::{XChaCha20Poly1305, Key, Nonce};
use aead::{Aead, KeyInit, Payload};
use rand::RngCore;
use anyhow::{Result, anyhow};

pub fn encrypt(key: &[u8; 32], plain: &[u8], aad: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plain, aad })
        .map_err(|_| anyhow!("encrypt failed"))?;
    Ok((nonce.to_vec(), ct))
}

pub fn decrypt(key: &[u8; 32], nonce: &[u8], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let plain = cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| anyhow!("decrypt failed"))?;
    Ok(plain)
}
// TODO: use ZeroizeOnDrop or reference key is  clean after use 
// tbh i want to use, ZeroizeOnDrop in dilithium. is minimally security bt good enough for just hackclub demo 