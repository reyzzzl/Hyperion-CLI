use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use std::fs::{self, OpenOptions};
use std::io::{self, Write, Read};
use std::path::PathBuf;
use std::net::TcpStream;
use std::thread;
use std::sync::{Arc, Mutex};
use std::sync::mpsc;
use std::time::Duration;
use dirs::home_dir;
use zeroize::{Zeroize, Zeroizing};
use crate::crypto::kyber;
use crate::crypto::dilithium;
use crate::crypto::kdf;
use crate::crypto::xchacha;
use crate::crypto::ratchet::{Ratchet, RatchetState};
use crate::protocol::handshake;
use crate::protocol::message::{pack_msg, unpack_msg};
use crate::storage::db::SessionDB;
use crate::storage::trust::TrustStore;
use crate::transport::tor::TorTransport;

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
    },
}

pub fn run(args: Args) -> Result<()> {
    let home = home_dir()
        .ok_or_else(|| anyhow!("HOME directory not found"))?
        .join(".hyperion");
    fs::create_dir_all(&home)?;
    let mut pwd = args.password;
    let res = match args.command {
        Command::Init => cmd_init(&pwd, &home),
        Command::Export { kyber, dilithium } => cmd_export(&pwd, &home, kyber, dilithium),
        Command::Host { port } => cmd_host(&pwd, &home, port, args.tor),
        Command::Connect { host, port } => cmd_connect(&pwd, &home, host, port, args.tor),
    };
    pwd.zeroize();
    res
}

fn cmd_init(password: &str, home: &PathBuf) -> Result<()> {
    let path = home.join("identity.bin");
    let (ky_pk, ky_sk) = kyber::keypair()?;
    let (dil_pk, dil_sk) = dilithium::keypair()?;
    let salt = rand::random::<[u8; 32]>();
    let key = kdf::derive_key(password.as_bytes(), &salt)?;
    let data = (ky_pk, ky_sk, dil_pk, dil_sk);
    let mut plain = bincode::serialize(&data)?;
    let (nonce, ct) = xchacha::encrypt(&key, &plain, &[])?;
    plain.zeroize();

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
// FIXME: unused some cryptographic logic
// this is for p2p only
// jm using a regular tcp loop for simplicity, but do not connect more than 1 person
// the stdin will collide during fingerprint verification. im too lazy to create an input queue
fn cmd_host(password: &str, home: &PathBuf, port: u16, use_tor: bool) -> Result<()> {
    let (_ky_pk, ky_sk, _dil_pk, dil_sk) = load_identity(password, home)?;
    let db = Arc::new(Mutex::new(SessionDB::new(&home.join("sessions.db"), password)?));
    let trust_path = home.join("trusted_clients.json");
    let trust_store = Arc::new(Mutex::new(TrustStore::new(&trust_path)?));

    if use_tor {
        println!("Tor hidden service: configure torrc manually.");
        println!("  HiddenServiceDir /var/lib/tor/hyperion/");
        println!("  HiddenServicePort {} 127.0.0.1:{}", port, port);
        println!("Then restart Tor and run without --tor");
        return Ok(());
    }

    let listener = std::net::TcpListener::bind(("0.0.0.0", port))?;
    println!("Listening on port {}", port);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let addr = stream.peer_addr()?;
                println!("Connection from {}", addr);
                let ky_sk_clone = kyber::SecretKey(ky_sk.0.clone());
                let dil_sk_clone = dilithium::SecretKey(dil_sk.0.clone());
                let db_clone = Arc::clone(&db);
                let trust_store_clone = Arc::clone(&trust_store);
                let trust_path_clone = trust_path.clone();
                let pwd = Zeroizing::new(password.to_string());
                let home_clone = home.clone();
                thread::spawn(move || {
                    let _pwd = pwd;
                    if let Err(e) = handle_client(
                        stream,
                        ky_sk_clone,
                        dil_sk_clone,
                        db_clone,
                        trust_store_clone,
                        &trust_path_clone,
                        &_pwd,
                        &home_clone,
                    ) {
                        eprintln!("Client error: {}", e);
                    }
                });
            }
            Err(e) => eprintln!("Accept error: {}", e),
        }
    }
    Ok(())
}

fn cmd_connect(password: &str, home: &PathBuf, host: String, port: u16, use_tor: bool) -> Result<()> {
    let (my_ky_pk, _my_ky_sk, my_dil_pk, my_dil_sk) = load_identity(password, home)?;
    let db = Arc::new(Mutex::new(SessionDB::new(&home.join("sessions.db"), password)?));

    println!("Enter peer's Kyber public key (hex):");
    let mut peer_ky_hex = String::new();
    io::stdin().read_line(&mut peer_ky_hex)?;
    let peer_ky_pk = hex::decode(peer_ky_hex.trim())
        .map_err(|_| anyhow!("Invalid Kyber public key hex"))?;
    if peer_ky_pk.len() != 1568 {
        return Err(anyhow!("Kyber public key must be 1568 bytes"));
    }

    println!("Enter peer's Dilithium public key (hex):");
    let mut peer_dil_hex = String::new();
    io::stdin().read_line(&mut peer_dil_hex)?;
    let peer_dil_pk = hex::decode(peer_dil_hex.trim())
        .map_err(|_| anyhow!("Invalid Dilithium public key hex"))?;

    println!("Connecting to {}:{}", host, port);
    let stream = if use_tor {
        let tor = TorTransport::new()?;
        tor.connect(&host, port)?
    } else {
        TcpStream::connect((host.as_str(), port))?
    };
    stream.set_nodelay(true)?;

    let (my_eph_pk, ct, sig, (send, recv)) = handshake::initiator_handshake(&peer_ky_pk, &my_dil_sk, &peer_dil_pk)?;
    let handshake_msg = pack_msg(1, &[my_eph_pk.as_slice(), ct.as_slice(), sig.as_slice(), my_dil_pk.as_slice()].concat())?;
    send_frame(&stream, &handshake_msg)?;

    let resp = recv_frame(&stream)?;
    let (typ, payload) = unpack_msg(&resp)?;
    if typ != 2 {
        return Err(anyhow!("Invalid response"));
    }
    if payload.len() < 1568 + dilithium::signature_len() + peer_dil_pk.len() {
        return Err(anyhow!("Response too short"));
    }
    let sv_eph = &payload[0..1568];
    let sig_start = 1568;
    let sig_end = sig_start + dilithium::signature_len();
    let sv_sig = &payload[sig_start..sig_end];
    let sv_dil_pk = &payload[sig_end..];

    let msg_to_verify = [my_dil_pk.as_slice(), sv_eph].concat();
    if !dilithium::verify(&peer_dil_pk, &msg_to_verify, sv_sig) {
        return Err(anyhow!("Server signature invalid"));
    }

    let send_arr: [u8; 32] = send.as_slice().try_into().map_err(|_| anyhow!("invalid send chain"))?;
    let recv_arr: [u8; 32] = recv.as_slice().try_into().map_err(|_| anyhow!("invalid recv chain"))?;
    let ratchet = Ratchet::from_state(RatchetState::new(send_arr, recv_arr));

    {
        let mut db_guard = db.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        db_guard.save_session(&host, &peer_dil_pk, &ratchet.get_state())?;
    }

    println!("Session established. Type /quit to exit.");
    chat_loop(stream, ratchet, db, &host, &peer_dil_pk, true)?;
    Ok(())
}

fn handle_client(
    mut stream: TcpStream,
    ky_sk: kyber::SecretKey,
    dil_sk: dilithium::SecretKey,
    db: Arc<Mutex<SessionDB>>,
    trust_store: Arc<Mutex<TrustStore>>,
    trust_path: &PathBuf,
    password: &str,
    home: &PathBuf,
) -> Result<()> {
    stream.set_nodelay(true)?;
    let data = recv_frame(&stream)?;
    let (typ, payload) = unpack_msg(&data)?;
    if typ != 1 {
        return Err(anyhow!("Invalid handshake type"));
    }
    if payload.len() < 1568 + 1568 + dilithium::signature_len() {
        return Err(anyhow!("Handshake too short"));
    }
    let cl_eph = &payload[0..1568];
    let ct_start = 1568;
    let ct_end = 1568 + 1568;
    let ct = &payload[ct_start..ct_end];
    let sig_start = ct_end;
    let sig_end = sig_start + dilithium::signature_len();
    let sig = &payload[sig_start..sig_end];
    let cl_dil_pk = &payload[sig_end..];

    {
        let mut store = trust_store.lock().unwrap();
        let fingerprint = hex::encode(&cl_dil_pk[..32]);
        if !store.contains(&cl_dil_pk) {
            println!("\n[!] New client connecting. Fingerprint: {}", fingerprint);
            println!("Trust this client? (y/n): ");
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            if input.trim().to_lowercase() != "y" {
                return Err(anyhow!("Client not trusted"));
            }
            store.insert(&cl_dil_pk);
            store.save(trust_path)?;
            println!("Client trusted and saved.");
        } else {
            let stored = store.get(&cl_dil_pk).unwrap();
            if stored.as_slice() != cl_dil_pk {
                return Err(anyhow!("Client key mismatch! Possible MITM"));
            }
        }
    }

    let msg_to_verify = [cl_dil_pk, cl_eph, ct].concat();
    if !dilithium::verify(cl_dil_pk, &msg_to_verify, sig) {
        return Err(anyhow!("Client signature invalid"));
    }

    // ths server uses static kyber key for decaps (no ephemeral server key)
    // TODO: adding emphemeral server key
    // ths simplifies session management bt means forward secrecy is client-only
    // TODO: adding forward secrency for 2 user, this is mybe can consumn time long 
    let ss = kyber::decaps(&ky_sk, ct)?;
    let root = kdf::hkdf(None, &ss, b"handshake", 64)?;
    let send = kdf::hkdf(Some(&root), b"resp-send", b"ratchet", 32)?;
    let recv = kdf::hkdf(Some(&root), b"init-send", b"ratchet", 32)?;
    drop(ss);
    drop(root);

    let send_arr: [u8; 32] = send.as_slice().try_into().map_err(|_| anyhow!("invalid send chain"))?;
    let recv_arr: [u8; 32] = recv.as_slice().try_into().map_err(|_| anyhow!("invalid recv chain"))?;
    let ratchet = Ratchet::from_state(RatchetState::new(send_arr, recv_arr));

    let (sv_eph_pk, _) = kyber::keypair()?;
    let msg_to_sign = [cl_dil_pk, &sv_eph_pk].concat();
    let server_sig = dilithium::sign(&dil_sk, &msg_to_sign)?;
    let (_, _, my_dil_pk, _) = load_identity(password, home)?;

    let resp = [sv_eph_pk.as_slice(), server_sig.as_slice(), my_dil_pk.as_slice()].concat();
    send_frame(&stream, &pack_msg(2, &resp)?)?;

    let peer_id = format!("{}", stream.peer_addr()?);
    {
        let db_guard = db.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        db_guard.save_session(&peer_id, cl_dil_pk, &ratchet.get_state())?;
    }

    println!("Session with {} established.", peer_id);
    chat_loop(stream, ratchet, db, &peer_id, cl_dil_pk, false)?;
    Ok(())
}

fn chat_loop(
    mut stream: TcpStream,
    mut ratchet: Ratchet,
    db: Arc<Mutex<SessionDB>>,
    peer_id: &str,
    peer_dil_pk: &[u8],
    is_client: bool,
) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_millis(200)))?;
    let (tx, rx) = mpsc::channel();
    let input_thread = thread::spawn(move || {
        let stdin = io::stdin();
        let mut input = String::new();
        while let Ok(_) = stdin.read_line(&mut input) {
            let trimmed = input.trim();
            if trimmed == "/quit" {
                break;
            }
            if !trimmed.is_empty() {
                if tx.send(trimmed.to_string()).is_err() {
                    break;
                }
            }
            input.clear();
        }
    });

    loop {
        if let Ok(msg) = rx.try_recv() {
            let ct = ratchet.encrypt(msg.as_bytes())?;
            send_frame(&stream, &pack_msg(2, &ct)?)?;
            {
                let mut db_guard = db.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                db_guard.save_session(peer_id, peer_dil_pk, &ratchet.get_state())?;
            }
        }

        match recv_frame(&stream) {
            Ok(data) => {
                let (typ, payload) = unpack_msg(&data)?;
                if typ == 2 {
                    let plain = Zeroizing::new(ratchet.decrypt(&payload)?);
                    let prefix = if is_client { "Server" } else { "Client" };
                    println!("\n[{}] {}", prefix, String::from_utf8_lossy(&plain));
                    print!("> ");
                    io::stdout().flush()?;
                    {
                        let mut db_guard = db.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                        db_guard.save_session(peer_id, peer_dil_pk, &ratchet.get_state())?;
                    }
                }
            }
            Err(ref e) if e.downcast_ref::<std::io::Error>().map_or(false, |io| io.kind() == std::io::ErrorKind::WouldBlock) => {}
            Err(e) => {
                println!("Connection error: {}", e);
                break;
            }
        }
    }
    if let Err(e) = input_thread.join() {
        eprintln!("Input thread error: {:?}", e);
    }
    Ok(())
}

fn send_frame(mut stream: &TcpStream, data: &[u8]) -> Result<()> {
    let len = data.len() as u32;
    let mut buf = len.to_be_bytes().to_vec();
    buf.extend_from_slice(data);
    stream.write_all(&buf)?;
    Ok(())
}

fn recv_frame(mut stream: &TcpStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    let mut read = 0;
    while read < 4 {
        let n = stream.read(&mut len_buf[read..])?;
        if n == 0 {
            return Err(anyhow!("Connection closed"));
        }
        read += n;
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 10 * 1024 * 1024 {
        return Err(anyhow!("Frame too large: {}", len));
    }
    let mut data = vec![0u8; len];
    let mut read = 0;
    while read < len {
        let n = stream.read(&mut data[read..])?;
        if n == 0 {
            return Err(anyhow!("Connection closed"));
        }
        read += n;
    }
    Ok(data)
}

fn load_identity(password: &str, home: &PathBuf) -> Result<(Vec<u8>, kyber::SecretKey, Vec<u8>, dilithium::SecretKey)> {
    let path = home.join("identity.bin");
    let data = fs::read(path)?;
    if data.len() < 56 {
        return Err(anyhow!("corrupt identity file"));
    }
    let salt: [u8; 32] = data[0..32].try_into().unwrap();
    let nonce = &data[32..56];
    let ct = &data[56..];
    let key = kdf::derive_key(password.as_bytes(), &salt)?;
    let mut plain = xchacha::decrypt(&key, nonce, ct, &[])?;
    let (ky_pk, ky_sk, dil_pk, dil_sk): (Vec<u8>, kyber::SecretKey, Vec<u8>, dilithium::SecretKey) =
        bincode::deserialize(&plain)?;
    plain.zeroize();
    Ok((ky_pk, ky_sk, dil_pk, dil_sk))
}