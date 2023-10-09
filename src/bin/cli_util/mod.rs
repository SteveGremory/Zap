use std::{
    fs::{self, File},
    io::BufWriter,
};

use clap::{Parser, Subcommand, ValueEnum};
use simple_logger::SimpleLogger;
use zap::{password::{EncryptionType, EncryptionSecret}, error::ZapError};
use zapf::{pack_files, unpack_files};

fn init_logger(level: Verbosity) -> Result<(), log::SetLoggerError> {
    let level = match level {
        Verbosity::Quiet => log::LevelFilter::Off,
        Verbosity::Normal => log::LevelFilter::Error,
        Verbosity::Verbose => log::LevelFilter::Info,
        Verbosity::Debug => log::LevelFilter::Trace,
    };

    SimpleLogger::new()
        .with_level(level)
        .without_timestamps()
        .init()
}

#[derive(Debug, Clone, ValueEnum)]
pub enum Verbosity {
    Quiet,
    Normal,
    Verbose,
    Debug,
}

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
        log_level: Verbosity,

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
        log_level: Verbosity,
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
                log_level,
            } => Self::archive(input, output, encryption, keypath, log_level),
            Command::Extract {
                input,
                output,
                encryption,
                keypath,
                log_level,
            } => Self::extract(input, output, encryption, keypath, log_level),
        }
    }

    fn archive(input: String, output: String, encryption: Option<EncryptionType>, keypath: Option<String>, log_level: Verbosity) -> Result<(), ZapError> {

        init_logger(log_level)?;

        log::error!("pid: {}", std::process::id());

        let enc: Option<EncryptionSecret> =  match encryption {
            Some(inner) => Some(EncryptionSecret::try_from((inner, keypath))?),
            None => None
        };

        zap::compress_directory(
            &input, 
            "/tmp/unpacked",
            enc
        )?;

        let out_file = File::create(output).expect("Could not create file");

        let mut out_writer = BufWriter::new(out_file);

        pack_files("/tmp/unpacked", &mut out_writer)?;
        
        Ok(fs::remove_dir_all("/tmp/unpacked")?)
    }

    fn extract(input: String, output: String, decryption: Option<EncryptionType>, keypath: Option<String>, log_level: Verbosity) -> Result<(), ZapError> {
        init_logger(log_level)?;

        log::error!("pid: {}", std::process::id());
        
        let enc: Option<EncryptionSecret> =  match decryption {
            Some(inner) => Some(EncryptionSecret::try_from((inner, keypath))?),
            None => None
        };

        // Need to check if this function validates path names
        // to prevent directory traversal.
        unpack_files(input, "/tmp/unpacked")?;

        zap::decompress_directory(
            "/tmp/unpacked", 
            &output,
            enc
        )?;

        Ok(fs::remove_dir_all("/tmp/unpacked")?)
        //Ok(())
    }
}
