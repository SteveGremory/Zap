mod encryption;
mod logging;
mod password;

use std::{
    fs::{self, File},
    io::BufWriter,
};

use clap::{Parser, Subcommand};

use log::info;
use zap::{
    encryption::EncryptionSecret,
    error::{EncryptionKeyError, EncryptionSecretError, ZapError},
};

use zapf::{pack_files, unpack_files};

use crate::cli_util::{
    logging::init_logger,
    password::{get_password_confirm, get_password_noconf},
};

use self::{encryption::EncryptionType, logging::Verbosity};

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
        keypath: Option<String>,
        #[arg(short, long, default_value = "normal")]
        verbosity: Verbosity,
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
        keypath: Option<String>,
        #[arg(short, long, default_value = "normal")]
        verbosity: Verbosity,
    },
    List {
        archive: String,
        #[arg(short, long, default_value = "normal")]
        verbosity: Verbosity,
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
                verbosity,
            } => Self::archive(input, output, encryption, keypath, verbosity),
            Command::Extract {
                input,
                output,
                encryption,
                keypath,
                verbosity,
            } => Self::extract(input, output, encryption, keypath, verbosity),
            Command::List { archive, verbosity } => Self::list(archive, verbosity),
        }
    }

    fn archive(
        input: String,
        output: String,
        encryption: Option<EncryptionType>,
        keypath: Option<String>,
        verbosity: Verbosity,
    ) -> Result<(), ZapError> {
        preamble(verbosity)?;

        let enc: Option<EncryptionSecret> = match encryption {
            Some(inner) => match inner {
                EncryptionType::Password => Some(EncryptionSecret::Password(
                    match get_password_confirm(256) {
                        Ok(pass) => pass,
                        Err(e) => return Err(e.into()),
                    },
                )),
                EncryptionType::Key => match keypath {
                    Some(path) => Some(EncryptionSecret::Key(path)),
                    None => {
                        return Err(EncryptionSecretError::Key(
                            EncryptionKeyError::KeyfileNotProvided,
                        )
                        .into())
                    }
                },
            },
            None => None,
        };

        zap::compress_directory(&input, "/tmp/unpacked", enc)?;

        let out_file = File::create(output).expect("Could not create file");

        let mut out_writer = BufWriter::new(out_file);

        pack_files("/tmp/unpacked", &mut out_writer)?;

        Ok(fs::remove_dir_all("/tmp/unpacked")?)
    }

    fn extract(
        input: String,
        output: String,
        decryption: Option<EncryptionType>,
        keypath: Option<String>,
        verbosity: Verbosity,
    ) -> Result<(), ZapError> {
        preamble(verbosity)?;

        let enc: Option<EncryptionSecret> = match decryption {
            Some(inner) => match inner {
                EncryptionType::Password => {
                    Some(EncryptionSecret::Password(match get_password_noconf(256) {
                        Ok(pass) => pass,
                        Err(e) => return Err(e.into()),
                    }))
                }
                EncryptionType::Key => match keypath {
                    Some(path) => Some(EncryptionSecret::Key(path)),
                    None => {
                        return Err(EncryptionSecretError::Key(
                            EncryptionKeyError::KeyfileNotProvided,
                        )
                        .into())
                    }
                },
            },
            None => None,
        };

        // Need to check if this function validates path names
        // to prevent directory traversal.
        unpack_files(input, "/tmp/unpacked")?;

        zap::decompress_directory("/tmp/unpacked", &output, enc)?;

        Ok(fs::remove_dir_all("/tmp/unpacked")?)
        //Ok(())
    }

    fn list(archive: String, verbosity: Verbosity) -> Result<(), ZapError> {
        preamble(verbosity)?;

        info!("Listing archive: {}", archive);

        unimplemented!("Archive listing not yet implemented");
    }
}

fn preamble(verbosity: Verbosity) -> Result<(), ZapError> {
    init_logger(verbosity)?;

    log::debug!("pid: {}", std::process::id());

    Ok(())
}
