use std::{
    fs::{self, File},
    io::{self, BufWriter},
};

use clap::Parser;
use zapf::pack_files;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Zap is a simple program to compress/encrypt the a folder."
)]
struct Args {
    /// Input folder
    input: String,

    /// Output file
    output: String,

    /// Whether to encrypt the data
    #[arg(short, long)]
    encrypt: bool,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();

    if args.encrypt {
        todo!("Encryption has not been implemented yet.");
    }

    zap::compress_directory(&args.input, "/tmp/stuff").await?;

    let out_file = File::create(&args.output).expect("Could not create file");
    let mut out_writer = BufWriter::new(out_file);

    pack_files("/tmp/stuff", &mut out_writer)?;

    fs::remove_dir_all("/tmp/stuff")?;

    Ok(())
}
