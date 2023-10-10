// External
use std::io::{
    Write,
    Read,
    Error
};

use super::{EncryptionModule, DecryptionModule, EncryptionAlgorithm, DecryptionAlgorithm};

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

impl <T> EncryptorPassthrough<T>
where T: Write
{
    pub fn new(writer: T) -> Self {
        EncryptorPassthrough {
            inner: writer
        }
    }
}

impl <T> From<T> for EncryptorPassthrough<T>
where T: Write
{
    fn from(writer: T) -> Self {
        EncryptorPassthrough::new(writer)
    }
}

impl <T> EncryptionModule for EncryptorPassthrough<T>
where T: Write
{
    fn finalise(mut self) -> Result<(), Error> {
        self.flush()
    }
}

impl <T> Write for EncryptorPassthrough<T>
where T: Write
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

impl <T> DecryptorPassthrough<T>
where T: Read
{
    pub fn new(reader: T) -> Self {
        DecryptorPassthrough {
            inner: reader
        }
    }
}

impl <T> From<T> for DecryptorPassthrough<T>
where T: Read
{
    fn from(reader: T) -> Self {
        DecryptorPassthrough::new(reader)
    }
}

impl <T> DecryptionModule for DecryptorPassthrough<T>
where T: Read
{
    fn finalise(self) -> Result<(), Error> {
        Ok(())
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
where T: Write
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
where T: Read
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