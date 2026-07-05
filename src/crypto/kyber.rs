use oqs::kem::{Kem, Algorithm};
use zeroize::{ZeroizeOnDrop, Zeroizing};
use serde::{Serialize, Deserialize};
use serde_bytes;
use anyhow::{Result, anyhow};

#[derive(Serialize, Deserialize, ZeroizeOnDrop)]
pub struct SecretKey(#[serde(with = "serde_bytes")] pub Vec<u8>);

pub fn keypair() -> Result<(Vec<u8>, SecretKey)> {
    let kem = Kem::new(Algorithm::Kyber1024).map_err(|e| anyhow!("{:?}", e))?;
    let (pk, sk) = kem.keypair().map_err(|e| anyhow!("{:?}", e))?;
    Ok((pk.into_vec(), SecretKey(sk.into_vec())))
}

pub fn encaps(pk: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    let kem = Kem::new(Algorithm::Kyber1024).map_err(|e| anyhow!("{:?}", e))?;
    let pk_obj = kem.public_key_from_bytes(pk).ok_or_else(|| anyhow!("invalid public key"))?;
    let (ct, ss) = kem.encapsulate(&pk_obj).map_err(|e| anyhow!("{:?}", e))?;
    Ok((ct.into_vec(), Zeroizing::new(ss.into_vec())))
}

pub fn decaps(sk: &SecretKey, ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let kem = Kem::new(Algorithm::Kyber1024).map_err(|e| anyhow!("{:?}", e))?;
    let ct_obj = kem.ciphertext_from_bytes(ct).ok_or_else(|| anyhow!("invalid ciphertext"))?;
    let sk_obj = kem.secret_key_from_bytes(&sk.0).ok_or_else(|| anyhow!("invalid secret key"))?;
    let ss = kem.decapsulate(&sk_obj, &ct_obj).map_err(|e| anyhow!("{:?}", e))?;
    Ok(Zeroizing::new(ss.into_vec()))
}
// TODO: i wanna using cache kem instance next avoid repeated allocation
// options is: lazy_static/once cell,
// accept &kem parameter