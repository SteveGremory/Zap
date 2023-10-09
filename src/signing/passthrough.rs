// External
use std::io::{Error, Read, Write};

use crate::compression::{Compress, Decompress};

use super::{Sign, Verify};

pub struct SignerPassthrough<T> {
    inner: T,
}

impl<T> SignerPassthrough<T>
where
    T: Compress,
{
    pub fn new(writer: T) -> Self {
        SignerPassthrough { inner: writer }
    }
}

impl<T> From<T> for SignerPassthrough<T>
where
    T: Compress,
{
    fn from(writer: T) -> Self {
        SignerPassthrough::new(writer)
    }
}

impl<T> Sign for SignerPassthrough<T>
where
    T: Compress,
{
    fn finalise(self) -> Result<Option<Vec<u8>>, Error> {
        self.inner.finalise()?;
        Ok(None)
    }
}

impl<T> Write for SignerPassthrough<T>
where
    T: Compress,
{
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }
}

pub struct VerifierPassthrough<T> {
    inner: T,
}

impl<T> VerifierPassthrough<T>
where
    T: Decompress,
{
    pub fn new(reader: T) -> Self {
        VerifierPassthrough { inner: reader }
    }
}

impl<T> From<T> for VerifierPassthrough<T>
where
    T: Decompress,
{
    fn from(reader: T) -> Self {
        VerifierPassthrough::new(reader)
    }
}

impl<T> Verify for VerifierPassthrough<T>
where
    T: Decompress,
{
    fn finalise(self) -> Result<Option<Vec<u8>>, Error> {
        self.inner.finalise()?;
        Ok(None)
    }
}

impl<T> Read for VerifierPassthrough<T>
where
    T: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}
