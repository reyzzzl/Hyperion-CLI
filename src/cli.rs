// SPDX-License-Identifier: GPL-3.0
use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use dirs::home_dir;
use crate::crypto::kyber;
use crate::crypto::dilithium;
use crate::crypto::kdf;
use crate::crypto::xchacha;
use crate::transport::local;

#[derive(Parser)]
#[command(name = "hyperion", about = "quantum messenger")]
pub struct Args {
    #[arg(short, long, required = true)]
    pub password: String,
    #[arg(long)]
    pub tor: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    Init,
    Export {
        #[arg(long)]
        kyber: bool,
        #[arg(long)]
        dilithium: bool,
    },
    Host {
        #[arg(short, long, default_value = "9876")]
        port: u16,
    },
    Connect {
        #[arg(short, long, default_value = "127.0.0.1")]
        host: String,
        #[arg(short, long, default_value = "9876")]
        port: u16,
        #[arg(long)]
        qr: bool,
    },
}

pub fn run(args: Args) -> Result<()> {
    let home = home_dir()
        .ok_or_else(|| anyhow!("HOME directory not found"))?
        .join(".hyperion");
    fs::create_dir_all(&home)?;
    match args.command {
        Command::Init => cmd_init(&args.password, &home),
        Command::Export { kyber, dilithium } => cmd_export(&args.password, &home, kyber, dilithium),
        Command::Host { port } => cmd_host(&args.password, &home, port),
        Command::Connect { host, port, qr } => cmd_connect(&args.password, &home, host, port, qr),
    }
}

fn cmd_init(password: &str, home: &PathBuf) -> Result<()> {
    let path = home.join("identity.bin");
    let (ky_pk, ky_sk) = kyber::keypair()?;
    let (dil_pk, dil_sk) = dilithium::keypair()?;
    let salt = rand::random::<[u8; 32]>();
    let key = kdf::derive_key(password.as_bytes(), &salt)?;
    let data = (ky_pk, ky_sk, dil_pk, dil_sk);
    let plain = bincode::serialize(&data)?;
    let (nonce, ct) = xchacha::encrypt(&key, &plain, &[])?;
    let mut out = salt.to_vec();
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                anyhow!("identity already exists")
            } else {
                anyhow!("failed to create identity: {}", e)
            }
        })?;
    file.write_all(&out)?;
    file.sync_all()?;
    println!("identity created");
    Ok(())
}

fn cmd_export(password: &str, home: &PathBuf, kyber: bool, dilithium: bool) -> Result<()> {
    let (ky_pk, _, dil_pk, _) = load_identity(password, home)?;
    if kyber {
        println!("{}", hex::encode(ky_pk));
    }
    if dilithium {
        println!("{}", hex::encode(dil_pk));
    }
    Ok(())
}

fn cmd_host(password: &str, home: &PathBuf, port: u16) -> Result<()> {
    let (_ky_pk, _ky_sk, _dil_pk, _dil_sk) = load_identity(password, home)?;
    let _stream = local::listen(port)?;
    println!("listening on port {}", port);
    println!("handshake not implemented (demo)");
    Ok(())
}

fn cmd_connect(password: &str, home: &PathBuf, host: String, port: u16, _qr: bool) -> Result<()> {
    let (_ky_pk, _ky_sk, _dil_pk, _dil_sk) = load_identity(password, home)?;
    let _stream = local::connect(&host, port)?;
    println!("connected to {}:{}", host, port);
    println!("handshake not implemented (demo)");
    Ok(())
}

fn load_identity(
    password: &str,
    home: &PathBuf,
) -> Result<(Vec<u8>, kyber::SecretKey, Vec<u8>, dilithium::SecretKey)> {
    let path = home.join("identity.bin");
    let data = fs::read(path)?;
    if data.len() < 56 {
        return Err(anyhow!("corrupt identity file"));
    }
    let salt: [u8; 32] = data[0..32].try_into().unwrap();
    let nonce = &data[32..56];
    let ct = &data[56..];
    let key = kdf::derive_key(password.as_bytes(), &salt)?;
    let plain = xchacha::decrypt(&key, nonce, ct, &[])?;
    let (ky_pk, ky_sk, dil_pk, dil_sk): (Vec<u8>, kyber::SecretKey, Vec<u8>, dilithium::SecretKey) =
        bincode::deserialize(&plain)?;
    Ok((ky_pk, ky_sk, dil_pk, dil_sk))
}