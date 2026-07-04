use argon2::{Argon2, Params, Algorithm, Version};
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroizing;
use anyhow::{Result, anyhow};

const HKDF_MAX: usize = 16320;

pub fn derive_key(pwd: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut out = Zeroizing::new([0u8; 32]);
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::default());
    argon2.hash_password_into(pwd, salt, &mut *out)
        .map_err(|e| anyhow!("{}", e))?;
    Ok(out)
}

pub fn hkdf(salt: Option<&[u8]>, ikm: &[u8], info: &[u8], length: usize) -> Result<Zeroizing<Vec<u8>>> {
    if length > HKDF_MAX {
        return Err(anyhow!("hkdf length too large"));
    }
    let hk = Hkdf::<Sha512>::new(salt, ikm);
    let mut out = vec![0u8; length];
    hk.expand(info, &mut out).map_err(|e| anyhow!("{}", e))?;
    Ok(Zeroizing::new(out))
}