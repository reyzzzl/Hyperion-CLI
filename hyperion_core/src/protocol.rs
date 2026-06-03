// SPDX-License-Identifier: GPL-3.0
use serde::{Serialize, Deserialize};
use crate::error::HyperionError;

pub const MAGIC: [u8; 4] = *b"HYPR";
pub const VERSION: u8 = 1;

#[derive(Serialize, Deserialize)]
pub struct HandshakeMessage {
    pub version: u8,
    pub nonce_pk: Vec<u8>,
    pub kem_ciphertext: Vec<u8>,
    pub signature: Vec<u8>,
    pub identity_pk: Vec<u8>,
}

impl HandshakeMessage {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.push(self.version);
        out.extend_from_slice(&(self.nonce_pk.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.nonce_pk);
        out.extend_from_slice(&(self.kem_ciphertext.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.kem_ciphertext);
        out.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&(self.identity_pk.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.identity_pk);
        out
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, HyperionError> {
        if data.len() < 8 {
            return Err(HyperionError::InvalidHandshake);
        }
        if &data[0..4] != MAGIC {
            return Err(HyperionError::InvalidHandshake);
        }
        let version = data[4];
        if version != VERSION {
            return Err(HyperionError::UnknownVersion(version));
        }
        let mut pos = 5;
        // add nonce_pk
        if data.len() < pos + 2 {
            return Err(HyperionError::InvalidHandshake);
        }
        let len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if data.len() < pos + len {
            return Err(HyperionError::InvalidHandshake);
        }
        let nonce_pk = data[pos..pos + len].to_vec();
        pos += len;
        // kem_ciphertext
        if data.len() < pos + 2 {
            return Err(HyperionError::InvalidHandshake);
        }
        let len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if data.len() < pos + len {
            return Err(HyperionError::InvalidHandshake);
        }
        let kem_ciphertext = data[pos..pos + len].to_vec();
        pos += len;
        // create signature encrypt
        if data.len() < pos + 2 {
            return Err(HyperionError::InvalidHandshake);
        }
        let len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if data.len() < pos + len {
            return Err(HyperionError::InvalidHandshake);
        }
        let signature = data[pos..pos + len].to_vec();
        pos += len;
        // adding identity_pk
        if data.len() < pos + 2 {
            return Err(HyperionError::InvalidHandshake);
        }
        let len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if data.len() < pos + len {
            return Err(HyperionError::InvalidHandshake);
        }
        let identity_pk = data[pos..pos + len].to_vec();
        Ok(Self {
            version,
            nonce_pk,
            kem_ciphertext,
            signature,
            identity_pk,
        })
    }
}

#[derive(Serialize, Deserialize)]
pub struct ServerResponse {
    pub nonce_pk: Vec<u8>,
    pub signature: Vec<u8>,
    pub identity_pk: Vec<u8>,
}

impl ServerResponse {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.push(VERSION);
        out.extend_from_slice(&(self.nonce_pk.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.nonce_pk);
        out.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&(self.identity_pk.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.identity_pk);
        out
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, HyperionError> {
        if data.len() < 8 {
            return Err(HyperionError::InvalidHandshake);
        }
        if &data[0..4] != MAGIC {
            return Err(HyperionError::InvalidHandshake);
        }
        let version = data[4];
        if version != VERSION {
            return Err(HyperionError::UnknownVersion(version));
        }
        let mut pos = 5;
        // double nonce_pk
        if data.len() < pos + 2 {
            return Err(HyperionError::InvalidHandshake);
        }
        let len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if data.len() < pos + len {
            return Err(HyperionError::InvalidHandshake);
        }
        let nonce_pk = data[pos..pos + len].to_vec();
        pos += len;
        // double signature
        if data.len() < pos + 2 {
            return Err(HyperionError::InvalidHandshake);
        }
        let len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if data.len() < pos + len {
            return Err(HyperionError::InvalidHandshake);
        }
        let signature = data[pos..pos + len].to_vec();
        pos += len;
        // double identity_pk
        if data.len() < pos + 2 {
            return Err(HyperionError::InvalidHandshake);
        }
        let len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if data.len() < pos + len {
            return Err(HyperionError::InvalidHandshake);
        }
        let identity_pk = data[pos..pos + len].to_vec();
        Ok(Self {
            nonce_pk,
            signature,
            identity_pk,
        })
    }
}