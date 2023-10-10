pub mod aes_gcm_256;
pub mod chachapoly;
pub mod passthrough;
pub mod xchachapoly;

//Internal
use crate::error::EncryptorInitError;

// External

use std::io::{Error, Read, Write};

pub struct EncryptorMode;
pub struct DecryptorMode;

pub trait EncryptionModule: Write {
    fn finalise(self) -> Result<(), Error>;
}
pub trait DecryptionModule: Read {
    fn finalise(self) -> Result<(), Error>;
}

pub trait EncryptionAlgorithm<T>
where
    T: Write,
{
    type Encryptor: EncryptionModule;

    fn encryptor(&self, writer: T) -> Result<Self::Encryptor, EncryptorInitError>;
}

pub trait DecryptionAlgorithm<T>
where
    T: Read,
{
    type Decryptor: DecryptionModule;

    fn decryptor(&self, reader: T) -> Result<Self::Decryptor, EncryptorInitError>;
}

#[derive(Default, Clone)]
pub enum EncryptionSecret {
    #[default]
    None,
    Password(Vec<u8>),
    Key(String),
}

#[derive(Default)]
pub enum EncryptionType {
    #[default]
    Passthrough,
    XChaCha,
    AesGcm,
    ChaCha,
}