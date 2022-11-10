// External
use std::{
    io::{
        Write,
        Read,
        Error
    }
};

use crate::compression::Cleanup;

use super::{Signer, Verifier};

pub fn signer_passthrough<T>(input: Result<T, Error>) -> Result<SignerPassthrough<T>, Error>
where T: Write
{
    match input {
        Err(e) => Err(e),
        Ok(input) => Ok(
            SignerPassthrough{
                inner: input
            }
        )
    }
}

pub struct SignerPassthrough<T>
{
    inner: T
}

impl<T> Write for SignerPassthrough<T>
where T: Write
{
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }
}

impl<T, U> Signer<U> for SignerPassthrough<T>
where T: Cleanup<U>
{
    fn signature(self) -> Result<Vec<u8>, Error> {
        Ok([].to_vec())
    }

    fn cleanup(self) -> Result<Vec<u8>, Error> {
        self.inner.cleanup()?;
        Ok([].to_vec())
    }
}

pub fn verifier_passthrough<T>(input: Result<T, Error>) -> Result<VerifierPassthrough<T>, Error>
where T: Read
{
    match input {
        Err(e) => Err(e),
        Ok(input) => Ok(
            VerifierPassthrough {
                inner: input
            }
        )
    }
}

pub struct VerifierPassthrough<T>
{
    inner: T
}

impl<T> Read for VerifierPassthrough<T>
where T: Read
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<T, U> Verifier<U> for VerifierPassthrough<T>
where T: Cleanup<U>
{
    fn signature(self) -> Result<bool, Error> {
        Ok(true)
    }

    fn cleanup(self) -> Result<bool, Error> {
        self.inner.cleanup()?;
        Ok(true)
    }
}