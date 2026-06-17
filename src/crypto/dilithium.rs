// SPDX-License-Identifier: GPL-3.0
use oqs::sig::Sig;
use zeroize::Zeroize;
use serde::{Serialize, Deserialize};
use serde_bytes;
use anyhow::{Result, anyhow};

#[derive(Serialize, Deserialize)]
pub struct SecretKey(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub fn keypair() -> Result<(Vec<u8>, SecretKey)> {
    let sig = Sig::new("Dilithium5").map_err(|e| anyhow!(e))?;
    let (pk, sk) = sig.keypair().map_err(|e| anyhow!(e))?;
    Ok((pk, SecretKey(sk)))
}

pub fn sign(sk: &SecretKey, msg: &[u8]) -> Result<Vec<u8>> {
    let sig = Sig::new("Dilithium5").map_err(|e| anyhow!(e))?;
    let s = sig.sign(msg, &sk.0).map_err(|e| anyhow!(e))?;
    Ok(s)
}

pub fn verify(pk: &[u8], msg: &[u8], sig_bytes: &[u8]) -> bool {
    Sig::new("Dilithium5")
        .ok()
        .and_then(|s| s.verify(msg, sig_bytes, pk).ok())
        .unwrap_or(false)
}

pub fn signature_len() -> usize {
    Sig::new("Dilithium5")
        .map(|s| s.signature_length())
        .unwrap_or(4887)
}