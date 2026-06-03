// SPDX-License-Identifier: GPL-3.0
use blake2::{Blake2b512, Digest};
use sha2::Sha512;
use hmac::{Hmac, Mac};
use zeroize::Zeroizing;

pub const SALT_SIZE: usize = 32;
pub const KEY_LEN: usize = 32;

pub fn derive_key(pwd: &[u8], salt: &[u8]) -> Zeroizing<[u8; KEY_LEN]> {
    let mut hasher = Blake2b512::new();
    hasher.update(salt);
    hasher.update(pwd);
    let result = hasher.finalize();
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    out.copy_from_slice(&result[..KEY_LEN]);
    out
}

pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    type HmacSha512 = Hmac<Sha512>;
    let prk = if salt.is_empty() {
        let mut mac = HmacSha512::new_from_slice(&[0u8; 64]).unwrap();
        mac.update(ikm);
        mac.finalize().into_bytes().to_vec()
    } else {
        let mut mac = HmacSha512::new_from_slice(salt).unwrap();
        mac.update(ikm);
        mac.finalize().into_bytes().to_vec()
    };
    let mut out = Vec::with_capacity(length);
    let mut t = vec![];
    let mut i = 1u8;
    while out.len() < length {
        let mut mac = HmacSha512::new_from_slice(&prk).unwrap();
        mac.update(&t);
        mac.update(info);
        mac.update(&[i]);
        let block = mac.finalize().into_bytes();
        t = block.to_vec();
        out.extend_from_slice(&t);
        i += 1;
    }
    out.truncate(length);
    out
}