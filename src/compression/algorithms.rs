// Internal
use super::Cleanup;

// External
use std::io::{
    Error,
    ErrorKind,
    Write,
};
use lz4_flex::frame::{
    FrameEncoder,
    FrameDecoder
};

pub fn lz4_encoder<T>(input: Result<T, std::io::Error>) -> Result<Lz4_Encoder<T>, std::io::Error>
where T: Write
{
    Ok( Lz4_Encoder { 
        inner: (FrameEncoder::new(input?)) 
    })
}

pub struct Lz4_Encoder<T>
where T: Write
{
    inner: FrameEncoder<T>
}

impl<T> Write for Lz4_Encoder<T>
where T: Write
{
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }
}

impl<T> Cleanup<T> for Lz4_Encoder<T>
where T: Write
{
    fn cleanup(self) -> Result<T, Error>
    {
        match self.inner.finish()
        {
            Ok(w) => Ok(w),
            Err(e) => Err(Error::from(
                ErrorKind::Interrupted
            ))
        }
    }
}