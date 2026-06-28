use anyhow::{Result, anyhow};
use zeroize::Zeroizing;
use crate::crypto::kyber;
use crate::crypto::dilithium;
use crate::crypto::kdf;

pub fn initiator_handshake(
    peer_ky_pk: &[u8],
    my_dil_sk: &dilithium::SecretKey,
    peer_dil_pk: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>))> {
// generate emphemeral keypair for PFS 
// TODO: kyber::keypair() is produce sk unusedd
// drop zeroize for mutation
    let (my_eph_pk, _) = kyber::keypair()?;

// encapsulate pk for create shared scret
    let (ct, ss) = kyber::encaps(peer_ky_pk)?;
    let msg_to_sign = [peer_dil_pk, &my_eph_pk, &ct].concat();
    let sig = dilithium::sign(my_dil_sk, &msg_to_sign)?;

// KDF derivation for got rachet key
    let root = kdf::hkdf(None, &ss, b"handshake", 64)?;
    let send = kdf::hkdf(Some(&root), b"init-send", b"ratchet", 32)?;
    let recv = kdf::hkdf(Some(&root), b"resp-send", b"ratchet", 32)?;

// drop for wipe data in memory
    drop(ss);
    drop(root);
    Ok((my_eph_pk, ct, sig, (send, recv)))
}