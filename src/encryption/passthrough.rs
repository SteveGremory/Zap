// External
use std::io::{
    Write,
    Read,
    Error
};

use crate::compression::{Compress, Decompress};

use super::{Encrypt, Decrypt, EncryptionAlgorithm, DecryptionAlgorithm};

pub struct EncryptionPassthrough {

}

impl EncryptionPassthrough {
    pub fn new() -> Self {
        EncryptionPassthrough {

        }
    }
}

impl Default for EncryptionPassthrough {
    fn default() -> Self {
        EncryptionPassthrough::new()
    }
}

pub struct EncryptorPassthrough<T> {
    inner: T
}

impl <T> Encrypt for EncryptorPassthrough<T>
where T: Compress
{
    fn finalise(self) -> Result<(), Error> {
        self.inner.finalise()
    }
}

impl <T> Write for EncryptorPassthrough<T>
where T: Compress
{
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }
}

pub struct DecryptorPassthrough<T>
{
    inner: T
}

impl <T> Decrypt for DecryptorPassthrough<T>
where T: Decompress
{
    fn finalise(self) -> Result<(), Error> {
        self.inner.finalise()
    }
}

impl <T> Read for DecryptorPassthrough<T> 
where T: Read
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl <T> EncryptionAlgorithm<T> for EncryptionPassthrough
where T: Compress
{
    type Encryptor = EncryptorPassthrough<T>;

    fn encryptor(&self, writer: T) -> Result<Self::Encryptor, crate::error::EncryptorInitError> {
        Ok(
            EncryptorPassthrough {
                inner: writer
            }
        )
    }
}

impl <T> DecryptionAlgorithm<T> for EncryptionPassthrough
where T: Decompress
{
    type Decryptor = DecryptorPassthrough<T>;

    fn decryptor(&self, reader: T) -> Result<Self::Decryptor, crate::error::EncryptorInitError> {
        Ok(
            DecryptorPassthrough {
                inner: reader
            }
        )
    }
}