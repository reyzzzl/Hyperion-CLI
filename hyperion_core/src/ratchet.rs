// SPDX-License-Identifier: GPL-3.0
use blake2::{Blake2b512, Digest};
use serde::{Serialize, Deserialize};
use crate::xchacha::{xenc, xdec, NONCE_SIZE};

pub const MAX_SEQ_WINDOW: usize = 1000;

#[derive(Serialize, Deserialize, Clone)]
pub struct RatchetState {
    root_key: [u8; 64],
    send_chain: [u8; 32],
    recv_chain: [u8; 32],
    send_seq: u64,
    recv_seq: u64,
}

impl RatchetState {
    pub fn new(root_key: [u8; 64], send_chain: [u8; 32], recv_chain: [u8; 32]) -> Self {
        Self {
            root_key,
            send_chain,
            recv_chain,
            send_seq: 0,
            recv_seq: 0,
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

    pub fn encrypt(&mut self, plain: &[u8]) -> Vec<u8> {
        let msg_key = self.derive_message_key(&self.state.send_chain);
        let mut hasher = Blake2b512::new();
        hasher.update(&self.state.send_chain);
        hasher.update(b"chain");
        let new_chain = hasher.finalize();
        self.state.send_chain.copy_from_slice(&new_chain[..32]);
        let seq = self.state.send_seq;
        self.state.send_seq += 1;
        let (nonce, ct) = xenc(&msg_key, plain, &seq.to_be_bytes());
        let mut out = seq.to_be_bytes().to_vec();
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        if ciphertext.len() < 16 {
            return Err("Ciphertext too short".into());
        }
        let seq = u64::from_be_bytes(ciphertext[0..8].try_into().unwrap());
        if seq <= self.state.recv_seq {
            return Err(format!("Replay: seq {} <= last {}", seq, self.state.recv_seq));
        }
        if seq > self.state.recv_seq + (MAX_SEQ_WINDOW as u64) {
            return Err(format!("Too far ahead: {} > {} + {}", seq, self.state.recv_seq, MAX_SEQ_WINDOW));
        }
        let nonce = &ciphertext[8..8 + NONCE_SIZE];
        let ct = &ciphertext[8 + NONCE_SIZE..];
        let msg_key = self.derive_message_key(&self.state.recv_chain);
        let mut hasher = Blake2b512::new();
        hasher.update(&self.state.recv_chain);
        hasher.update(b"chain");
        let new_chain = hasher.finalize();
        self.state.recv_chain.copy_from_slice(&new_chain[..32]);
        self.state.recv_seq = seq;
        xdec(&msg_key, nonce, ct, &seq.to_be_bytes())
    }

    fn derive_message_key(&self, chain: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Blake2b512::new();
        hasher.update(chain);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result[..32]);
        out
    }

    pub fn get_state(&self) -> RatchetState {
        self.state.clone()
    }
}