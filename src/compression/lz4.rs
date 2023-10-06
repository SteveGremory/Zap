use std::io::{
    Write,
    Read
};
use lz4_flex::frame::{
    FrameEncoder,
    FrameDecoder
};

use crate::{error::CompressorInitError, encryption::{Encrypt, Decrypt}};

use super::{Compress, CompressionAlgorithm, DecompressionAlgorithm, Decompress};

pub struct Lz4Algorithm {
}

impl <T> CompressionAlgorithm<T> for Lz4Algorithm
where T: Encrypt
{
    type Compressor = Lz4Compressor<T>;

    fn compressor(&self, io: T) -> Result<Self::Compressor, CompressorInitError> {
        Ok(Lz4Compressor::new(io))
    }
}

impl Lz4Algorithm {
    pub fn new() -> Lz4Algorithm {
        Lz4Algorithm {
        }
    }
}

impl Default for Lz4Algorithm {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Lz4Compressor<T>
where T: Encrypt
{
    encoder: FrameEncoder<T>,
}

impl <T> Lz4Compressor<T> 
where T: Encrypt
{
    pub fn new(io: T) -> Self {
        Lz4Compressor {
            encoder: FrameEncoder::new(io),
        }
    }
}

impl <T> Compress for Lz4Compressor<T> 
where T: Encrypt
{
    fn finalise(self) -> Result<(), std::io::Error> {
        match self.encoder.finish() {
            Ok(w) => w.finalise(),
            Err(e) => Err(
                std::io::Error::new(
                    std::io::ErrorKind::Other, 
                    format!("Encryption failed: {}", e)
                )
            )
        }
    }
}

impl <T> Write for Lz4Compressor<T>
where T: Encrypt
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        
        let len = self.encoder.write(buf)?;
        
        Ok(len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.encoder.flush()
    }
}

pub struct Lz4Deompressor<T>
where T: Decrypt
{
    decoder: FrameDecoder<T>,
}

impl <T> Lz4Deompressor<T>
where T: Decrypt
{
    pub fn new(io: T) -> Self {
        Lz4Deompressor {
            decoder: FrameDecoder::new(io),
        }
    }
}

impl <T> Decompress for Lz4Deompressor<T> 
where T: Decrypt
{
    fn finalise(self) -> Result<(), std::io::Error> {
        self.decoder.into_inner().finalise()
    }
}

impl <T> Read for Lz4Deompressor<T>
where T: Decrypt
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        
        let len = self.decoder.read(buf)?;
        
        Ok(len)
    }
}

impl <T> DecompressionAlgorithm<T> for Lz4Algorithm
where T: Decrypt
{
    type Decompressor = Lz4Deompressor<T>;

    fn decompressor(&self, io: T) -> Result<Self::Decompressor, CompressorInitError> {
        Ok(Lz4Deompressor::new(io))
    }
}