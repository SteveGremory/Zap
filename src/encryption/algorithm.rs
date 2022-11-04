use crate::compression::Cleanup;

//Internal
use super::Encryptor;

// External
use std::{
    io::{
        Write,
        Error,
    }
};
use openssl::{
    symm::Cipher
};

pub fn aes256<T>(
    psk: &'static [u8;256], 
    iv: &'static [u8;256], 
    writer: Result<T, Error>
) -> Result<Encryptor<'static, T>, Error> where T: Write
{
    Ok(
        Encryptor { 
            cipher: Cipher::aes_256_cbc(),
            key_len: 256,
            key: psk, 
            iv: iv,
            writer: writer?
        }
    )
}

pub fn encryption_passthrough<T>(input: Result<T, Error>) -> Result<EncryptionPassthrough<T>, Error>
where T: Write+Cleanup<T>
{
    match input {
        Err(e) => Err(e),
        Ok(input) => Ok(
            EncryptionPassthrough{
                inner: input
            }
        )
    }
}

pub struct EncryptionPassthrough<T>
where T: Write+Cleanup<T>
{
    inner: T
}

impl<T> Write for EncryptionPassthrough<T>
where T: Write+Cleanup<T>
{
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }
}

impl<T> Cleanup<T> for EncryptionPassthrough<T>
where T: Cleanup<T>+Write
{
    fn cleanup(self) ->  Result<T, Error> {
        self.inner.cleanup()
    }
}