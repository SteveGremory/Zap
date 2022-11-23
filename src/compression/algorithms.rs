// Internal
use super::Cleanup;

use core::panic;
// External
use std::io::{
    Error,
    ErrorKind,
    Write,
    Read
};
use lz4_flex::frame::{
    FrameEncoder,
    FrameDecoder
};

pub fn lz4_encoder<T>(input: Result<T, std::io::Error>) -> Result<Lz4Encoder<T>, std::io::Error>
where T: Write
{
    Ok( Lz4Encoder { 
        inner: (FrameEncoder::new(input?)) 
    })
}

pub struct Lz4Encoder<T>
where T: Write
{
    inner: FrameEncoder<T>
}

impl<T> Write for Lz4Encoder<T>
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

impl<T, U> Cleanup<U> for Lz4Encoder<T>
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
                    format!("Encryption failed: {}", e.to_string())
                )
            )
        }
    }
}

pub fn lz4_decoder<T>(input: Result<T, std::io::Error>) -> Result<Lz4Decoder<T>, std::io::Error>
where T: Read
{
    Ok( Lz4Decoder { 
        inner: (FrameDecoder::new(input?)) 
    })
}

pub struct Lz4Decoder<T>
where T: Read
{
    inner: FrameDecoder<T>
}

impl<T> Read for Lz4Decoder<T>
where T: Read
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        
        let len = self.inner.read(buf)?;
        
        Ok(len)
    }
}

impl<T, U> Cleanup<U> for Lz4Decoder<T>
where T: Read+Cleanup<U>
{
    fn cleanup(self) -> Result<U, Error>
    {
        self.inner.into_inner().cleanup()
    }
}


