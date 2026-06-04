// SPDX-License-Identifier: GPL-3.0
use argon2::{Argon2, Params, Algorithm, Version};
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroizing;

pub const SALT_SIZE: usize = 32;
pub const KEY_LEN: usize = 32;

// downing the for pw to argon2id
pub fn derive_key(pwd: &[u8], salt: &[u8]) -> Zeroizing<[u8; KEY_LEN]> {
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::default());
    argon2.hash_password_into(pwd, salt, &mut *out).expect("argon2id error");
    out
}

// hdkf-sha512 for salt this optional
pub fn hkdf(salt: Option<&[u8]>, ikm: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha512>::new(salt, ikm);
    let mut out = vec![0u8; length];
    hk.expand(info, &mut out).unwrap(); // limited length
    out
}