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
use crate::internal::Cleanup;

pub fn compress<T, U, V>(mut input: T, output: Result<U, Error>) -> Result<Vec<u8>, Error>
where 
T: Read,
U: Write+Signer<V>,
V: Write
{
    // Unwrap our output
    let mut out = output?;
    copy(&mut input, &mut out)?;
    out.finalise()
}

pub fn decompress<T, U, V>(input: Result<T, Error>, mut output: U) -> Result<bool, Error>
where 
T: Read+Verifier<V>,
U: Write,
V: Read
{
    // Unwrap our input
    let mut inp = input?;
    copy(&mut inp, &mut output)?;
    inp.finalise()
}

// This and Decoder will end up being the generic compression
// structs so that we can swap algorithms out easily.
// They are both very straight forward and are pretty wysiwyg
pub struct Encoder<T>
where T: Write
{
    inner: FrameEncoder<T>
}

impl<T> Write for Encoder<T>
where T: Write
{
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let len = self.inner.write(buf)?;
        Ok(len)
    }
}

impl<T, U> Cleanup<U> for Encoder<T>
where T: Write+Cleanup<U>
{
    fn cleanup(self) -> Result<U, Error>
    {
        match self.inner.finish()
        {
            Ok(w) => w.cleanup(),
            Err(e) => Err(
                Error::new(
                    ErrorKind::Other, 
                    format!("Encryption failed: {}", e)
                )
            )
        }
    }
}

pub struct Decoder<T>
where T: Read
{
    inner: FrameDecoder<T>
}

impl<T> Read for Decoder<T>
where T: Read
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        
        let len = self.inner.read(buf)?;
        
        Ok(len)
    }
}

impl<T, U> Cleanup<U> for Decoder<T>
where T: Read+Cleanup<U>
{
    fn cleanup(self) -> Result<U, Error>
    {
        self.inner.into_inner().cleanup()
    }
}

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

