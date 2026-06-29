use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use zeroize::{Zeroize, Zeroizing};
use crate::crypto::xchacha;
use crate::crypto::kdf;
use crate::crypto::ratchet::RatchetState;

#[derive(Serialize, Deserialize)]
struct SessionEntry {
    peer_id: String,
    peer_dil_pk: Vec<u8>,
    ratchet_state: RatchetState,
}

pub struct SessionDB {
    pub path: PathBuf,
    password: String,
}

impl SessionDB {
    pub fn new(path: &PathBuf, password: &str) -> Result<Self> {
        Ok(Self {
            path: path.clone(),
            password: password.to_string(),
        })
    }
// read, description, and deserialized all session from disk
// return vector empty if file is None 
    fn load_all(&self) -> Result<Vec<SessionEntry>> {
        if !self.path.exists() {
            return Ok(vec![]);
        }
        let data = fs::read(&self.path)?;
        if data.is_empty() {
            return Ok(vec![]);
        }
// structure biner in disk
        let salt = &data[0..32];
        let nonce = &data[32..56];
        let ct = &data[56..];
// down encryption key  from psword and salt
        let key = kdf::derive_key(self.password.as_bytes(), salt)?;
//// ciphertext to plaintext json
        let mut plain = xchacha::decrypt(&key, nonce, ct, &[])?;
        let entries: Vec<SessionEntry> = serde_json::from_slice(&plain)?;
// zeroize 
        plain.zeroize();
        Ok(entries)
    }

    fn save_all(&self, entries: &[SessionEntry]) -> Result<()> {
        let mut plain = serde_json::to_vec(entries)?;
        let salt = rand::random::<[u8; 32]>();
        let key = kdf::derive_key(self.password.as_bytes(), &salt)?;
        let (nonce, ct) = xchacha::encrypt(&key, &plain, &[])?;
        plain.zeroize();
        let mut out = salt.to_vec();
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);

        let temp_path = self.path.with_extension("tmp");
        {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&temp_path)?;
            file.write_all(&out)?;
            file.sync_all()?;
        }
        fs::rename(&temp_path, &self.path)?;
        Ok(())
    }

    pub fn save_session(&self, peer_id: &str, peer_dil_pk: &[u8], ratchet_state: &RatchetState) -> Result<()> {
        let mut entries = self.load_all()?;
        entries.retain(|e| e.peer_id != peer_id);
        entries.push(SessionEntry {
            peer_id: peer_id.to_string(),
            peer_dil_pk: peer_dil_pk.to_vec(),
            ratchet_state: ratchet_state.clone(),
        });
        self.save_all(&entries)
    }

    pub fn load_session(&self, peer_id: &str) -> Result<Option<(Vec<u8>, RatchetState)>> {
        let entries = self.load_all()?;
        for e in entries {
            if e.peer_id == peer_id {
                return Ok(Some((e.peer_dil_pk, e.ratchet_state)));
            }
        }
        Ok(None)
    }
}

impl Drop for SessionDB {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}