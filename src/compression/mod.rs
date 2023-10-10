pub mod gzip;
pub mod lz4;
pub mod passthrough;
pub mod snappy;

use crate::error::CompressorInitError;

// External
use std::io::{Error, Read, Write};

pub struct CompressionMode;
pub struct DecompressionMode;

pub trait Compress: Write {
    fn finalise(self) -> Result<(), Error>;
}
pub trait Decompress: Read {
    fn finalise(self) -> Result<(), Error>;
}

pub trait CompressionAlgorithm<T>
where
    T: Write,
{
    type Compressor: Compress;

    fn compressor(&self, writer: T) -> Result<Self::Compressor, CompressorInitError>;
}

pub trait DecompressionAlgorithm<T>
where
    T: Read,
{
    type Decompressor: Decompress;

    fn decompressor(&self, reader: T) -> Result<Self::Decompressor, CompressorInitError>;
}

#[derive(Default, Debug, Clone)]
pub enum CompressionType {
    #[default]
    Passthrough,
    Lz4,
    Gzip,
    Snappy,
}

impl From<String> for CompressionType {
    fn from(s: String) -> Self {
        match s.as_str() {
            "passthrough" => Self::Passthrough,
            "lz4" => Self::Lz4,
            "gzip" => Self::Gzip,
            "snappy" => Self::Snappy,
            _ => Self::Passthrough,
        }
    }
}
