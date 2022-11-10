use std::{
    fs::{self, File},
    io::{self, BufWriter},
};

use clap::{Parser, Subcommand, ValueEnum};
use zapf::{pack_files, unpack_files};
use zap::{compression::algorithms::{lz4_decoder}};
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
        encrypt: Option<EncryptionType>,
        keypath: Option<String>
    },
    Extract {
        /// Input file
        input: String,

        /// Output folder
        output: String,

        /// Whether to encrypt the data
        /// String is either
        #[arg(short, long)]
        keypath: Option<String>,
    },
}

impl Command {
    async fn execute(self) -> io::Result<()> {
        match self {
            Command::Archive {
                input,
                output,
                encrypt,
                keypath,
            } => Self::archive(input, output, encrypt, keypath).await,
            Command::Extract {
                input,
                output,
                keypath,
            } => Self::extract(input, output, keypath).await,
        }
    }

    async fn archive(input: String, output: String, _encrypt: Option<EncryptionType>, _keypath: Option<String>) -> io::Result<()> {
        zap::compress_directory(
            &input, 
            "/tmp/stuff"
        ).await?;

        let out_file = File::create(&output).expect("Could not create file");

        let mut out_writer = BufWriter::new(out_file);

        pack_files("/tmp/stuff", &mut out_writer)?;
        /*match encrypt {
            Some(encryption_method) => {
                let out_file = File::create(format!("{}.tmp", &output))
                    .expect("Could not create file");

                let mut out_writer = BufWriter::new(out_file);

                pack_files("/tmp/stuff", &mut out_writer)?;

                match encryption_method {
                    Password => {
                        zap::encrypt_directory_pw(&output)?;
                        // remove packed file
                    },
                    Key => {
                        zap::encrypt_directory_key()?;
                    }
                }
            },
            None => {
                let out_file = File::create(&output)
                    .expect("Could not create file");

                let mut out_writer = BufWriter::new(out_file);

                pack_files("/tmp/stuff", &mut out_writer)?;
            }
        }*/

        fs::remove_dir_all("/tmp/stuff")
        
    }

    async fn extract(input: String, output: String, _decrypt: Option<String>) -> io::Result<()> {
        //dbg!(decrypt)
        //if decrypt {
          //  todo!("Decryption has not been implemented yet.");
        //}

        unpack_files(&input, "/tmp/unpacked")?;
        zap::decompress_directory(
            "/tmp/unpacked", 
            &output,
        ).await?;

        //fs::remove_dir_all("/tmp/unpacked")
        Ok(())
    }
}

#[derive(Debug, Clone, ValueEnum)]
enum EncryptionType {
    Password,
    Key
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();
    args.command.execute().await
}
