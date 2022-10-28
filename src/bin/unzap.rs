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
    about,
    long_about = "Zap: Decompress and/or decrypt a folder into a single file"
)]

struct Args {
    /// Input file
    input: String,

    /// Output folder
    output: String,

    /// Whether to encrypt the data
    #[arg(short, long)]
    encrypt: bool,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();

    unpack_files(&args.input, "/tmp/unpacked")?;
    zap::decompress_directory("/tmp/unpacked", &args.output).await?;

    fs::remove_dir_all("/tmp/unpacked")?;

    Ok(())
}
