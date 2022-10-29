use std::{
    fs::{self, File},
    io::{self, BufWriter},
};

use clap::{Parser, Subcommand};
use zapf::{pack_files, unpack_files};

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Zap is a simple program to compress/encrypt the a folder."
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Archive {
        /// Input folder
        input: String,
        /// Output file
        output: String,

        /// Whether to encrypt the data
        #[arg(short, long)]
        encrypt: bool,
    },
    Extract {
        /// Input file
        input: String,

        /// Output folder
        output: String,

        /// Whether to encrypt the data
        #[arg(short, long)]
        decrypt: bool,
    },
}

impl Command {
    async fn execute(self) -> io::Result<()> {
        match self {
            Command::Archive {
                input,
                output,
                encrypt,
            } => Self::archive(input, output, encrypt).await,
            Command::Extract {
                input,
                output,
                decrypt,
            } => Self::extract(input, output, decrypt).await,
        }
    }

    async fn archive(input: String, output: String, encrypt: bool) -> io::Result<()> {
        if encrypt {
            todo!("Encryption has not been implemented yet.");
        }

        zap::compress_directory(&input, "/tmp/stuff").await?;

        let out_file = File::create(&output).expect("Could not create file");
        let mut out_writer = BufWriter::new(out_file);

        pack_files("/tmp/stuff", &mut out_writer)?;

        fs::remove_dir_all("/tmp/stuff")
    }

    async fn extract(input: String, output: String, decrypt: bool) -> io::Result<()> {
        if decrypt {
            todo!("Decryption has not been implemented yet.");
        }

        unpack_files(&input, "/tmp/unpacked")?;
        zap::decompress_directory("/tmp/unpacked", &output).await?;

        fs::remove_dir_all("/tmp/unpacked")
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();
    args.command.execute().await
}
