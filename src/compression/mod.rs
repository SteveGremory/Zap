pub mod passthrough;
pub mod lz4;
pub mod gzip;
pub mod snappy;

use crate::{signing::{Signer, Verifier}, error::CompressorInitError};

// External
use std::io::{
    Error,
    Read,
    Write,
    copy,
    ErrorKind,
};
use lz4_flex::frame::{
    FrameEncoder,
    FrameDecoder
};

pub struct CompressionMode;
pub struct DecompressionMode;

pub trait Compress: Write {
    fn finalise(self) -> Result<(), Error>;
}
pub trait Decompress: Read {
    fn finalise(self) -> Result<(), Error>;
}

pub trait CompressionAlgorithm<T>
where T: Write
{
    type Compressor: Compress;

    fn compressor(&self, writer: T) -> Result<Self::Compressor, CompressorInitError>;
}

pub trait DecompressionAlgorithm<T>
where T: Read
{
    type Decompressor: Decompress;

    fn decompressor(&self, reader: T) -> Result<Self::Decompressor, CompressorInitError>;
}

#[derive(Default)]
pub enum CompressionType {
    #[default]
    Passthrough,
    Lz4,
    Gzip,
    Snappy,
}