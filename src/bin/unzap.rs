use std::{
    fs::{self},
    io::{self},
};

use clap::Parser;
use zapf::unpack_files;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Unzap is a simple program to decompress/decrypt a zapfile."
)]

struct Args {
    /// Input file
    input: String,

    /// Output folder
    output: String,

    /// Whether to encrypt the data
    #[arg(short, long)]
    decrypt: bool,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();

    if args.decrypt {
        todo!("Decryption has not been implemented yet.");
    }

    unpack_files(&args.input, "/tmp/unpacked")?;
    zap::decompress_directory("/tmp/unpacked", &args.output).await?;

    fs::remove_dir_all("/tmp/unpacked")?;

    Ok(())
}
