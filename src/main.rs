mod crypto;
mod error;
mod pipeline;
mod ts;

use std::io::{self, Write};
use std::path::PathBuf;

use clap::Parser;

/// HLS sample-encrypted MPEG-TS decryptor.
///
/// Decrypts elementary streams (H.264, AAC, AC-3) in MPEG-TS files
/// using AES-128-CBC per Apple's HLS Sample Encryption specification.
#[derive(Parser, Debug)]
#[command(name = "decrypt-mpegts", version, about)]
struct Args {
    /// Input .ts file path
    #[arg(short, long)]
    input: PathBuf,

    /// Output .ts file path
    #[arg(short, long)]
    output: PathBuf,

    /// AES-128 key as 32 hex characters
    #[arg(short, long)]
    key: String,

    /// AES-128 IV as 32 hex characters (defaults to all zeros)
    #[arg(long)]
    iv: Option<String>,

    /// Overwrite output file without prompting
    #[arg(short = 'y', long = "yes")]
    overwrite: bool,
}

fn parse_hex_16(s: &str, name: &str) -> Result<[u8; 16], error::Error> {
    let bytes = hex::decode(s)?;
    if bytes.len() != 16 {
        return Err(error::Error::Decrypt(format!(
            "{} must be exactly 16 bytes (32 hex chars), got {} bytes",
            name,
            bytes.len()
        )));
    }
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn confirm_overwrite(path: &PathBuf) -> bool {
    eprint!("Output file '{}' already exists. Overwrite? [y/N] ", path.display());
    io::stderr().flush().ok();
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    matches!(input.trim(), "y" | "Y" | "yes" | "YES")
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args = Args::parse();

    if !args.input.exists() {
        eprintln!("Error: input file '{}' not found", args.input.display());
        std::process::exit(1);
    }

    if args.output.exists() && !args.overwrite && !confirm_overwrite(&args.output) {
        eprintln!("Aborted.");
        std::process::exit(1);
    }

    let key = parse_hex_16(&args.key, "Key")?;
    let iv = match &args.iv {
        Some(iv_str) => parse_hex_16(iv_str, "IV")?,
        None => [0u8; 16],
    };

    pipeline::run(&args.input, &args.output, &key, &iv)?;

    Ok(())
}
