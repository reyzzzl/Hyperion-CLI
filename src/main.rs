mod cli;
mod crypto;
mod protocol;
mod storage;
mod transport;

use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    let args = cli::Args::parse();
    cli::run(args)
}