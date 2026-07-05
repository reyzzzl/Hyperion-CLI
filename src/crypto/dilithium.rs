use oqs::sig::{Sig, Algorithm};
use zeroize::{ZeroizeOnDrop};
use serde::{Serialize, Deserialize};
use serde_bytes;
use anyhow::{Result, anyhow};

#[derive(Serialize, Deserialize, ZeroizeOnDrop)]
pub struct SecretKey(#[serde(with = "serde_bytes")] pub Vec<u8>);

pub fn keypair() -> Result<(Vec<u8>, SecretKey)> {
    let sig = Sig::new(Algorithm::Dilithium5).map_err(|e| anyhow!("{:?}", e))?;
    let (pk, sk) = sig.keypair().map_err(|e| anyhow!("{:?}", e))?;
    Ok((pk.into_vec(), SecretKey(sk.into_vec())))
}

pub fn sign(sk: &SecretKey, msg: &[u8]) -> Result<Vec<u8>> {
    let sig = Sig::new(Algorithm::Dilithium5).map_err(|e| anyhow!("{:?}", e))?;
    let sk_obj = sig.secret_key_from_bytes(&sk.0).ok_or_else(|| anyhow!("invalid secret key"))?;
    let s = sig.sign(msg, &sk_obj).map_err(|e| anyhow!("{:?}", e))?;
    Ok(s.into_vec())
}

pub fn verify(pk: &[u8], msg: &[u8], sig_bytes: &[u8]) -> bool {
    Sig::new(Algorithm::Dilithium5)
        .ok()
        .and_then(|s| {
            let pk_obj = s.public_key_from_bytes(pk)?;
            let sig_obj = s.signature_from_bytes(sig_bytes)?;
            Some(s.verify(msg, &sig_obj, &pk_obj).is_ok())
        })
        .unwrap_or(false)
}

pub fn signature_len() -> usize {
    Sig::new(Algorithm::Dilithium5)
        .map(|s| s.length_signature())
        .unwrap_or(4595)
}
// TODO: change Vec<u8> with array/container
// constant if tht possible later
// use type array static default oqs or
// wrap with cotainer fixed-size is better for security 
// FIX: error handling more informative in function verify bc returns false if initialization fails in (.ok())