mod compression;
mod encryption;
mod logging;
mod password;

use std::{
    fs::{self, File},
    io::BufWriter,
};

use clap::{Parser, Subcommand};

use log::info;
use zap::{encryption::EncryptionSecret, error::ZapError};

use zapf::{pack_files, unpack_files};

use crate::cli_util::{logging::init_logger, password::get_password_confirm};

use self::{
    compression::{BinCompressionType, CompressionLevel},
    encryption::BinEncryptionType,
    logging::Verbosity,
    password::get_password_noconf,
};

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
        /// If SecretType is key then keypath must be provided
        #[arg(short, long)]
        keypath: Option<String>,
        #[arg(short, long, default_value = "normal")]
        verbosity: Verbosity,
        #[arg(long, short, default_value = "passthrough")]
        encryption_algorithm: BinEncryptionType,
        #[arg(long, short, default_value = "passthrough")]
        compression_algorithm: BinCompressionType,
        #[arg(long, default_value = "fastest")]
        compression_level: CompressionLevel,
    },
    Extract {
        /// Input file
        input: String,
        /// Output folder
        output: String,
        /// If SecretType is key then keypath must be provided
        #[arg(short, long)]
        keypath: Option<String>,
        #[arg(short, long, default_value = "normal")]
        verbosity: Verbosity,
        #[arg(long, short, default_value = "passthrough")]
        encryption_algorithm: BinEncryptionType,
        #[arg(long, short, default_value = "passthrough")]
        compression_algorithm: BinCompressionType,
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
                keypath,
                verbosity,
                encryption_algorithm,
                compression_algorithm,
                compression_level,
            } => Self::archive(
                input,
                output,
                keypath,
                verbosity,
                encryption_algorithm,
                compression_algorithm,
                compression_level,
            ),
            Command::Extract {
                input,
                output,
                keypath,
                verbosity,
                encryption_algorithm,
                compression_algorithm,
            } => Self::extract(
                input,
                output,
                keypath,
                verbosity,
                encryption_algorithm,
                compression_algorithm,
            ),
            Command::List { archive, verbosity } => Self::list(archive, verbosity),
        }
    }

    fn archive(
        input: String,
        output: String,
        keypath: Option<String>,
        verbosity: Verbosity,
        encryption_algorithm: BinEncryptionType,
        compression_algorithm: BinCompressionType,
        compression_level: CompressionLevel,
    ) -> Result<(), ZapError> {
        preamble(verbosity)?;

        let encryption_secret: EncryptionSecret = match (&encryption_algorithm, keypath) {
            (BinEncryptionType::Passthrough, _) => EncryptionSecret::None,
            (_, Some(path)) => EncryptionSecret::Key(path),
            (_, None) => EncryptionSecret::Password(match get_password_confirm(256) {
                Ok(pass) => pass,
                Err(e) => return Err(e.into()),
            }),
        };

        info!("Encryption: {:?}", encryption_algorithm);
        info!("Compression: {:?}", compression_algorithm);

        zap::compress_directory(
            &input,
            "/tmp/unpacked",
            encryption_algorithm.into(),
            encryption_secret,
            compression_algorithm.into(),
            compression_level.into(),
            zap::signing::SigningType::default(),
        )?;

        let out_file = File::create(output).expect("Could not create file");

        let mut out_writer = BufWriter::new(out_file);

        pack_files("/tmp/unpacked", &mut out_writer)?;

        Ok(fs::remove_dir_all("/tmp/unpacked")?)
    }

    fn extract(
        input: String,
        output: String,
        keypath: Option<String>,
        verbosity: Verbosity,
        encryption_algorithm: BinEncryptionType,
        compression_algorithm: BinCompressionType,
    ) -> Result<(), ZapError> {
        preamble(verbosity)?;

        let encryption_secret: EncryptionSecret = match (&encryption_algorithm, keypath) {
            (BinEncryptionType::Passthrough, _) => EncryptionSecret::None,
            (_, None) => EncryptionSecret::Password(match get_password_noconf(256) {
                Ok(pass) => pass,
                Err(e) => return Err(e.into()),
            }),
            (_, Some(path)) => EncryptionSecret::Key(path),
        };

        // Need to check if this function validates path names
        // to prevent directory traversal.
        unpack_files(input, "/tmp/unpacked")?;

        zap::decompress_directory(
            "/tmp/unpacked",
            &output,
            encryption_algorithm.into(),
            encryption_secret,
            compression_algorithm.into(),
            zap::signing::SigningType::default(),
        )?;

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
