use anyhow::Result;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

// truststore sve public key client
// save in the form of hex encoded string  as  key in hashmap for serialization json
#[derive(Serialize, Deserialize, Default)]
pub struct TrustStore {
    clients: HashMap<String, Vec<u8>>,
}

impl TrustStore {
// read trust store from file, if file empty return to empty store
    pub fn new(path: &PathBuf) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = fs::read(path)?;
        if data.is_empty() {
            return Ok(Self::default());
        }
        let store: TrustStore = serde_json::from_slice(&data)
            .map_err(|e| anyhow::anyhow!("Failed to parse trust store: {}", e))?;
        Ok(store)
    }

    pub fn save(&self, path: &PathBuf) -> Result<()> {
// save trust store to file
        let data = serde_json::to_vec_pretty(self)?;

// TODO: mybe next using lib tempfile
// add atomic write file
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        file.write_all(&data)?;
        file.sync_all()?;
        Ok(())
    }

// check key is registered in store or not
// return false if length key not less than 32byte
    pub fn contains(&self, key: &[u8]) -> bool {
        let fingerprint = hex::encode(&key[..32]);
        self.clients.contains_key(&fingerprint)
    }

// get data key based on 32bytes
    pub fn get(&self, key: &[u8]) -> Option<&Vec<u8>> {
        let fingerprint = hex::encode(&key[..32]);
        self.clients.get(&fingerprint)
    }

// TODO: next i think change sig to insert(&mut self, key: [u8; 32]), but its experimental
    pub fn insert(&mut self, key: &[u8]) {
// keep from message if slicing is fail 
        let fingerprint = hex::encode(&key[..32]);
        self.clients.insert(fingerprint, key.to_vec());
    }
}