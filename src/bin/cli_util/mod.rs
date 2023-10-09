use std::{
    fs::{self, File},
    io::BufWriter,
};

use clap::{Parser, Subcommand};
use zap::{password::{get_password_noconf, EncryptionType, EncryptionSecret}, error::ZapError};
use zapf::{pack_files, unpack_files};

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Zap is a simple program to compress/encrypt a folder."
)]

pub struct Args {
    #[command(subcommand)]
    command: Command,
}

impl Args {
    pub fn execute(self) -> Result<(), ZapError> {
        self.command.execute()
    }
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
    pub fn execute(self) -> Result<(), ZapError> {
        match self {
            Command::Archive {
                input,
                output,
                encryption,
                keypath,
            } => Self::archive(input, output, encryption, keypath),
            Command::Extract {
                input,
                output,
                encryption,
                keypath,
            } => Self::extract(input, output, encryption, keypath),
        }
    }

    fn archive(input: String, output: String, encryption: Option<EncryptionType>, keypath: Option<String>) -> Result<(), ZapError> {

        println!("{:?}", encryption);

        let enc =  match encryption {
            Some(inner) => Some(EncryptionSecret::try_from((inner, keypath))?),
            None => None
        };

        zap::compress_directory(
            &input, 
            "/tmp/stuff",
            enc
        )?;

        let out_file = File::create(output).expect("Could not create file");

        let mut out_writer = BufWriter::new(out_file);

        pack_files("/tmp/stuff", &mut out_writer)?;
        
        Ok(fs::remove_dir_all("/tmp/stuff")?)
        
    }

    fn extract(input: String, output: String, decryption: Option<EncryptionType>, keypath: Option<String>) -> Result<(), ZapError> {
        let mut pass = None;
        //let mut key = None;
        // At the moment, there is no way to tell if an archive uses encryption.
        // This will be rectified in future but for the moment, the user must tell zap 
        // to ask for a password.
        let enc =  match decryption {
            Some(inner) => Some(EncryptionSecret::try_from((inner, keypath))?),
            None => None
        };
        // Need to check if this function validates path names
        // to prevent directory traversal.
        unpack_files(input, "/tmp/unpacked")?;

        zap::decompress_directory(
            "/tmp/unpacked", 
            &output,
            pass
        )?;

        Ok(fs::remove_dir_all("/tmp/unpacked")?)
    }
}
