use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use std::io::{Read, Write};

use crate::{
    encryption::{DecryptionModule, EncryptionModule},
    error::CompressorInitError,
};

use super::{Compress, CompressionAlgorithm, Decompress, DecompressionAlgorithm};

pub struct GzipAlgorithm {
    level: Compression,
}

impl GzipAlgorithm {
    pub fn with_compression_level(level: Compression) -> GzipAlgorithm {
        GzipAlgorithm { level }
    }

    pub fn new() -> GzipAlgorithm {
        GzipAlgorithm {
            level: Compression::fast(),
        }
    }
}

impl<T> CompressionAlgorithm<T> for GzipAlgorithm
where
    T: EncryptionModule,
{
    type Compressor = GzipCompressor<T>;

    fn compressor(&self, io: T) -> Result<Self::Compressor, CompressorInitError> {
        Ok(GzipCompressor {
            encoder: GzEncoder::new(io, self.level),
        })
    }
}

impl<T> DecompressionAlgorithm<T> for GzipAlgorithm
where
    T: DecryptionModule,
{
    type Decompressor = GzipDeompressor<T>;

    fn decompressor(&self, io: T) -> Result<Self::Decompressor, CompressorInitError> {
        Ok(GzipDeompressor::new(io))
    }
}

impl Default for GzipAlgorithm {
    fn default() -> Self {
        Self::new()
    }
}

pub struct GzipCompressor<T>
where
    T: EncryptionModule,
{
    encoder: GzEncoder<T>,
}

impl<T> GzipCompressor<T>
where
    T: EncryptionModule,
{
    pub fn new(io: T) -> Self {
        GzipCompressor {
            encoder: GzEncoder::new(io, Compression::fast()),
        }
    }
}

impl<T> Compress for GzipCompressor<T>
where
    T: EncryptionModule,
{
    fn finalise(self) -> Result<(), std::io::Error> {
        match self.encoder.finish() {
            Ok(w) => w.finalise(),
            Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Encryption failed: {}", e), // TODO: better error handling
            )),
        }
    }
}

impl<T> Write for GzipCompressor<T>
where
    T: EncryptionModule,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let len = self.encoder.write(buf)?;

        Ok(len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.encoder.flush()
    }
}

pub struct GzipDeompressor<T>
where
    T: DecryptionModule,
{
    decoder: GzDecoder<T>,
}

impl<T> GzipDeompressor<T>
where
    T: DecryptionModule,
{
    pub fn new(io: T) -> Self {
        GzipDeompressor {
            decoder: GzDecoder::new(io),
        }
    }
}

impl<T> Decompress for GzipDeompressor<T>
where
    T: DecryptionModule,
{
    fn finalise(self) -> Result<(), std::io::Error> {
        self.decoder.into_inner().finalise()
    }
}

impl<T> Read for GzipDeompressor<T>
where
    T: DecryptionModule,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.decoder.read(buf)
    }
}
