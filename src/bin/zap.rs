use std::{
    fs::{self, File},
    io::{self, BufWriter},
};

use clap::{Parser, Subcommand, ValueEnum};
use zapf::{pack_files, unpack_files};
use zap::{internal::{get_password_confirm, get_password_noconf}};
#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Zap is a simple program to compress/encrypt a folder."
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
        encryption: Option<EncryptionType>,
        /// If EncryptionType is key then keypath must be provided
        #[arg(short, long)]
        keypath: Option<String>
    },
    Extract {
        /// Input file
        input: String,

        /// Output folder
        output: String,

        /// Whether to encrypt the data
        #[arg(short, long)]
        encryption: Option<EncryptionType>,
        /// If EncryptionType is key then keypath must be provided
        #[arg(short, long)]
        keypath: Option<String>
    },
}

impl Command {
    async fn execute(self) -> io::Result<()> {
        match self {
            Command::Archive {
                input,
                output,
                encryption,
                keypath,
            } => Self::archive(input, output, encryption, keypath).await,
            Command::Extract {
                input,
                output,
                encryption,
                keypath,
            } => Self::extract(input, output, encryption, keypath).await,
        }
    }

    async fn archive(input: String, output: String, encryption: Option<EncryptionType>, _keypath: Option<String>) -> io::Result<()> {

        let mut pass = None;
        //let mut key = None;
        // This will be update in future versions when there are more alorithms available.
        if let Some(enc) = encryption {
            match enc {
            EncryptionType::Password => {
                pass = Some(vec![0u8;10]);//Some(get_password_confirm(256)?);
            },
            // Unimplemented
            EncryptionType::Key => {
                match _keypath {
                    None => panic!("No keypath provided."),
                    Some(_s) => unimplemented!("Keys not currently supported.")
                }
            },}
        }
        

        zap::compress_directory(
            &input, 
            "/tmp/stuff",
            pass
        ).await?;

        let out_file = File::create(&output).expect("Could not create file");

        let mut out_writer = BufWriter::new(out_file);

        pack_files("/tmp/stuff", &mut out_writer)?;
        
        fs::remove_dir_all("/tmp/stuff")
        
    }

    async fn extract(input: String, output: String, decryption: Option<EncryptionType>, _keypath: Option<String>) -> io::Result<()> {
        let mut pass = None;
        //let mut key = None;
        // At the moment, there is no way to tell if an archive uses encryption.
        // This will be rectified in future but for the moment, the user must tell zap 
        // to ask for a password.
        if let Some(enc) = decryption {
            match enc {
            EncryptionType::Password => {
                pass = Some(get_password_noconf(256)?);
            },
            // Unimplemented
            EncryptionType::Key => {
                match _keypath {
                    None => panic!("No keypath provided."),
                    Some(_s) => unimplemented!("Keys not currently supported.")
                }
            },}
        }
        // Need to check if this function validates path names
        // to prevent directory traversal.
        unpack_files(&input, "/tmp/unpacked")?;

        zap::decompress_directory(
            "/tmp/unpacked", 
            &output,
            pass
        ).await?;

        fs::remove_dir_all("/tmp/unpacked")
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
