// SPDX-License-Identifier: GPL-3.0
use oqs::kem::Kem;
use zeroize::Zeroize;

pub struct SecretKey(pub Vec<u8>);

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub struct KyberKeypair {
    pub public: Vec<u8>,
    pub secret: SecretKey,
}

pub struct Kyber;

impl Kyber {
    const ALG: &'static str = "Kyber1024";

    pub fn keypair() -> Result<KyberKeypair, String> {
        let kem = Kem::new(Kyber::ALG).map_err(|e| e.to_string())?;
        let (pk, sk) = kem.keypair().map_err(|e| e.to_string())?;
        Ok(KyberKeypair {
            public: pk,
            secret: SecretKey(sk),
        })
    }

    pub fn encaps(pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
        let kem = Kem::new(Kyber::ALG).map_err(|e| e.to_string())?;
        let (ct, ss) = kem.encapsulate(pk).map_err(|e| e.to_string())?;
        Ok((ct, ss))
    }

    pub fn decaps(sk: &SecretKey, ct: &[u8]) -> Result<Vec<u8>, String> {
        let kem = Kem::new(Kyber::ALG).map_err(|e| e.to_string())?;
        let ss = kem.decapsulate(ct, &sk.0).map_err(|e| e.to_string())?;
        Ok(ss)
    }
}