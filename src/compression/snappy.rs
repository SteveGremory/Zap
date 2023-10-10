use std::io::{Read, Write};

use snap::{write::FrameEncoder, read::FrameDecoder};

use crate::{
    encryption::{DecryptionModule, EncryptionModule},
    error::CompressorInitError,
};

use super::{Compress, CompressionAlgorithm, Decompress, DecompressionAlgorithm};

pub struct SnappyAlgorithm {}

impl<T> CompressionAlgorithm<T> for SnappyAlgorithm
where
    T: EncryptionModule,
{
    type Compressor = SnappyCompressor<T>;

    fn compressor(&self, io: T) -> Result<Self::Compressor, CompressorInitError> {
        Ok(SnappyCompressor::new(io))
    }
}

impl<T> DecompressionAlgorithm<T> for SnappyAlgorithm
where
    T: DecryptionModule,
{
    type Decompressor = SnappyDeompressor<T>;

    fn decompressor(&self, io: T) -> Result<Self::Decompressor, CompressorInitError> {
        Ok(SnappyDeompressor::new(io))
    }
}

impl SnappyAlgorithm {
    pub fn new() -> SnappyAlgorithm {
        SnappyAlgorithm {}
    }
}

impl Default for SnappyAlgorithm {
    fn default() -> Self {
        Self::new()
    }
}

pub struct SnappyCompressor<T>
where
    T: EncryptionModule,
{
    encoder: FrameEncoder<T>,
}

impl<T> SnappyCompressor<T>
where
    T: EncryptionModule,
{
    pub fn new(io: T) -> Self {
        SnappyCompressor {
            encoder: FrameEncoder::new(io),
        }
    }
}

impl<T> Compress for SnappyCompressor<T>
where
    T: EncryptionModule,
{
    fn finalise(self) -> Result<(), std::io::Error> {
        match self.encoder.into_inner() {
            Ok(w) => w.finalise(),
            Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Encryption failed: {}", e), // TODO: better error handling
            )),
        }
    }
}

impl<T> Write for SnappyCompressor<T>
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

pub struct SnappyDeompressor<T>
where
    T: DecryptionModule,
{
    decoder: FrameDecoder<T>,
}

impl<T> SnappyDeompressor<T>
where
    T: DecryptionModule,
{
    pub fn new(io: T) -> Self {
        SnappyDeompressor {
            decoder: FrameDecoder::new(io),
        }
    }
}

impl<T> Decompress for SnappyDeompressor<T>
where
    T: DecryptionModule,
{
    fn finalise(self) -> Result<(), std::io::Error> {
        self.decoder.into_inner().finalise()
    }
}

impl<T> Read for SnappyDeompressor<T>
where
    T: DecryptionModule,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.decoder.read(buf)
    }
}
