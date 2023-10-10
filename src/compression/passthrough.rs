use std::io::{Read, Write};

use crate::{
    encryption::{DecryptionModule, EncryptionModule},
    error::CompressorInitError,
};

use super::{Compress, CompressionAlgorithm, Decompress, DecompressionAlgorithm};

pub struct PassthroughAlgorithm {}

impl<T> CompressionAlgorithm<T> for PassthroughAlgorithm
where
    T: EncryptionModule,
{
    type Compressor = PassthroughCompressor<T>;

    fn compressor(&self, io: T) -> Result<Self::Compressor, CompressorInitError> {
        Ok(PassthroughCompressor::new(io))
    }
}

impl<T> DecompressionAlgorithm<T> for PassthroughAlgorithm
where
    T: DecryptionModule,
{
    type Decompressor = PassthroughDeompressor<T>;

    fn decompressor(&self, io: T) -> Result<Self::Decompressor, CompressorInitError> {
        Ok(PassthroughDeompressor::new(io))
    }
}

impl PassthroughAlgorithm {
    pub fn new() -> PassthroughAlgorithm {
        PassthroughAlgorithm {}
    }
}

impl Default for PassthroughAlgorithm {
    fn default() -> Self {
        Self::new()
    }
}

pub struct PassthroughCompressor<T>
where
    T: EncryptionModule,
{
    inner: T,
}

impl<T> PassthroughCompressor<T>
where
    T: EncryptionModule,
{
    pub fn new(io: T) -> Self {
        PassthroughCompressor {
            inner: io,
        }
    }
}

impl<T> Compress for PassthroughCompressor<T>
where
    T: EncryptionModule,
{
    fn finalise(self) -> Result<(), std::io::Error> {
        self.inner.finalise()
    }
}

impl<T> Write for PassthroughCompressor<T>
where
    T: EncryptionModule,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let len = self.inner.write(buf)?;

        Ok(len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

pub struct PassthroughDeompressor<T>
where
    T: DecryptionModule,
{
    inner: T,
}

impl<T> PassthroughDeompressor<T>
where
    T: DecryptionModule,
{
    pub fn new(io: T) -> Self {
        PassthroughDeompressor {
            inner: io,
        }
    }
}

impl<T> Decompress for PassthroughDeompressor<T>
where
    T: DecryptionModule,
{
    fn finalise(self) -> Result<(), std::io::Error> {
        self.inner.finalise()
    }
}

impl<T> Read for PassthroughDeompressor<T>
where
    T: DecryptionModule,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}
