use blake2::{Blake2b512, Digest};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use anyhow::{Result, anyhow};
use zeroize::{Zeroize, Zeroizing};
use crate::crypto::xchacha;

pub const MAX_SEQ: usize = 1000;
// TODO: check if zeroize is actually needed hre or if its dead code
fn ser_chain<S>(key: &Zeroizing<[u8; 32]>, s: S) -> Result<S::Ok, S::Error>
where S: serde::Serializer {
    s.serialize_bytes(&**key)
}

fn de_chain<'de, D>(d: D) -> Result<Zeroizing<[u8; 32]>, D::Error>
where D: serde::Deserializer<'de> {
    use serde::de::Visitor;
    struct V;
    impl<'de> Visitor<'de> for V {
        type Value = Zeroizing<[u8; 32]>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("32 bytes")
        }
        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where E: serde::de::Error {
            let arr: [u8; 32] = v.try_into().map_err(|_| serde::de::Error::invalid_length(v.len(), &"32"))?;
            Ok(Zeroizing::new(arr))
        }
    }
    d.deserialize_bytes(V)
}

fn ser_skipped<S>(map: &BTreeMap<u64, Zeroizing<[u8; 32]>>, s: S) -> Result<S::Ok, S::Error>
where S: serde::Serializer {
    let plain: BTreeMap<u64, [u8; 32]> = map.iter().map(|(k, v)| (*k, **v)).collect();
    plain.serialize(s)
}

fn de_skipped<'de, D>(d: D) -> Result<BTreeMap<u64, Zeroizing<[u8; 32]>>, D::Error>
where D: serde::Deserializer<'de> {
    let plain: BTreeMap<u64, [u8; 32]> = BTreeMap::deserialize(d)?;
    Ok(plain.into_iter().map(|(k, v)| (k, Zeroizing::new(v))).collect())
}
// TODO: refactor get_state to avoid .clone(). check if passing  ownership r &mut works better here
#[derive(Serialize, Deserialize, Clone)]
pub struct RatchetState {
    #[serde(serialize_with = "ser_chain", deserialize_with = "de_chain")]
    send_chain: Zeroizing<[u8; 32]>,
    #[serde(serialize_with = "ser_chain", deserialize_with = "de_chain")]
    recv_chain: Zeroizing<[u8; 32]>,
    send_seq: u64,
    recv_seq: u64,
    #[serde(serialize_with = "ser_skipped", deserialize_with = "de_skipped")]
    skipped: BTreeMap<u64, Zeroizing<[u8; 32]>>,
}

impl RatchetState {
    pub fn new(send: [u8; 32], recv: [u8; 32]) -> Self {
        Self {
            send_chain: Zeroizing::new(send),
            recv_chain: Zeroizing::new(recv),
            send_seq: 0,
            recv_seq: 0,
            skipped: BTreeMap::new(),
        }
    }
}

pub struct Ratchet {
    state: RatchetState,
}

impl Ratchet {
    pub fn from_state(state: RatchetState) -> Self {
        Self { state }
    }

    pub fn encrypt(&mut self, plain: &[u8]) -> Result<Vec<u8>> {
        let mk = Zeroizing::new(Self::derive_message_key(&*self.state.send_chain));
        let new_chain = Self::step_chain(&*self.state.send_chain);
        self.state.send_chain = Zeroizing::new(new_chain);
        let seq = self.state.send_seq;
        self.state.send_seq = self.state.send_seq.checked_add(1).ok_or_else(|| anyhow!("send overflow"))?;
        let (nonce, ct) = xchacha::encrypt(&mk, plain, &seq.to_be_bytes())?;
        let mut out = seq.to_be_bytes().to_vec();
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 8 + 24 + 16 {
            return Err(anyhow!("ciphertext too short"));
        }
        let seq = u64::from_be_bytes(data[0..8].try_into().unwrap());
        let nonce = &data[8..32];
        let ct = &data[32..];

        if let Some(k) = self.state.skipped.remove(&seq) {
            return xchacha::decrypt(&k, nonce, ct, &seq.to_be_bytes());
        }

        if seq < self.state.recv_seq {
            return Err(anyhow!("replay"));
        }
        let jump = seq - self.state.recv_seq;
        if jump > MAX_SEQ as u64 {
            return Err(anyhow!("jump too large"));
        }

        let mut chain = Zeroizing::new(*self.state.recv_chain);
        while self.state.recv_seq < seq {
            let mk = Zeroizing::new(Self::derive_message_key(&*chain));
            self.state.skipped.insert(self.state.recv_seq, mk);
            *chain = Self::step_chain(&*chain);
            self.state.recv_seq = self.state.recv_seq.checked_add(1).ok_or_else(|| anyhow!("recv overflow"))?;
        }

        let mk = Zeroizing::new(Self::derive_message_key(&*chain));
        self.state.recv_chain = Zeroizing::new(*chain);
        self.state.recv_seq = self.state.recv_seq.checked_add(1).ok_or_else(|| anyhow!("recv overflow"))?;

        if self.state.skipped.len() > MAX_SEQ {
            let limit = self.state.recv_seq.saturating_sub(MAX_SEQ as u64);
            let to_remove: Vec<_> = self.state.skipped.keys().filter(|&&k| k < limit).cloned().collect();
            for k in to_remove {
                self.state.skipped.remove(&k);
            }
        }

        xchacha::decrypt(&mk, nonce, ct, &seq.to_be_bytes())
    }

    fn step_chain(chain: &[u8; 32]) -> [u8; 32] {
        let mut h = Blake2b512::new();
        h.update(chain);
        h.update(b"chain");
        let out = h.finalize();
        let mut r = [0u8; 32];
        r.copy_from_slice(&out[..32]);
        r
    }

    fn derive_message_key(chain: &[u8; 32]) -> [u8; 32] {
        let mut h = Blake2b512::new();
        h.update(chain);
        h.update(b"msg_key");
        let out = h.finalize();
        let mut r = [0u8; 32];
        r.copy_from_slice(&out[..32]);
        r
    }

    pub fn get_state(&self) -> RatchetState {
        self.state.clone()
    }
}