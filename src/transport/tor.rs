use anyhow::{Result, anyhow};
use socks::Socks5Stream;
use std::net::TcpStream;

pub struct TorTransport;

impl TorTransport {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }

// connect stream tor
    pub fn connect(&self, host: &str, port: u16) -> Result<TcpStream> {
        let stream = Socks5Stream::connect("127.0.0.1:9050", (host, port))
            .map_err(|e| anyhow!("Tor connection failed: {}", e))?;
        Ok(stream.into_inner())
    }
}