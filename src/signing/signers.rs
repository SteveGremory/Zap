// External
use std::{
    io::{
        Write,
        Error
    }
};

use crate::compression::Cleanup;

pub fn signer_passthrough<T>(input: Result<T, Error>) -> Result<SignerPassthrough<T>, Error>
where T: Write+Cleanup<T>
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
where T: Write+Cleanup<T>
{
    inner: T
}

impl<T> Write for SignerPassthrough<T>
where T: Write+Cleanup<T>
{
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }
}

impl<T> Cleanup<T> for SignerPassthrough<T>
where T: Write+Cleanup<T>
{
    fn cleanup(self) ->  Result<T, Error> {
        self.inner.cleanup()
    }
}