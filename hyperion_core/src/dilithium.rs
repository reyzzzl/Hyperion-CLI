// SPDX-License-Identifier: GPL-3.0
use oqs::sig::Sig;
use zeroize::Zeroize;

pub struct SecretKey(pub Vec<u8>);

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub struct DilithiumKeypair {
    pub public: Vec<u8>,
    pub secret: SecretKey,
}

pub struct Dilithium;

impl Dilithium {
    const ALG: &'static str = "Dilithium5";

    pub fn keypair() -> Result<DilithiumKeypair, String> {
        let sig = Sig::new(Dilithium::ALG).map_err(|e| e.to_string())?;
        let (pk, sk) = sig.keypair().map_err(|e| e.to_string())?;
        Ok(DilithiumKeypair {
            public: pk,
            secret: SecretKey(sk),
        })
    }

    pub fn sign(sk: &SecretKey, msg: &[u8]) -> Result<Vec<u8>, String> {
        let sig = Sig::new(Dilithium::ALG).map_err(|e| e.to_string())?;
        sig.sign(msg, &sk.0).map_err(|e| e.to_string())
    }

    pub fn verify(pk: &[u8], msg: &[u8], sig_bytes: &[u8]) -> bool {
        match Sig::new(Dilithium::ALG) {
            Ok(ver) => ver.verify(msg, sig_bytes, pk).unwrap_or(false),
            Err(_) => false,
        }
    }

    pub fn signature_len() -> usize {
        Sig::new(Dilithium::ALG)
            .map(|s| s.signature_length())
            .unwrap_or(4887)
    }
}