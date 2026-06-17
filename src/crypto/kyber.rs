// SPDX-License-Identifier: GPL-3.0
use oqs::kem::Kem;
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
    let kem = Kem::new("Kyber1024").map_err(|e| anyhow!(e))?;
    let (pk, sk) = kem.keypair().map_err(|e| anyhow!(e))?;
    Ok((pk, SecretKey(sk)))
}

pub fn encaps(pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let kem = Kem::new("Kyber1024").map_err(|e| anyhow!(e))?;
    let (ct, ss) = kem.encapsulate(pk).map_err(|e| anyhow!(e))?;
    Ok((ct, ss))
}

pub fn decaps(sk: &SecretKey, ct: &[u8]) -> Result<Vec<u8>> {
    let kem = Kem::new("Kyber1024").map_err(|e| anyhow!(e))?;
    let ss = kem.decapsulate(ct, &sk.0).map_err(|e| anyhow!(e))?;
    Ok(ss)
}