pub mod aes_gcm_256;
pub mod chachapoly;
pub mod passthrough;
pub mod xchachapoly;

//Internal
use crate::{internal::Cleanup, error::EncryptorInitError};

// External
use aes_gcm::{
    aead::{Aead, AeadMutInPlace},
    aes::Aes256,
    AeadCore, AesGcm, KeyInit, Nonce,
};

use chacha20::{
    cipher::{
        typenum::{UInt, UTerm},
        StreamCipherCoreWrapper,
    },
    ChaChaCore,
};
use chacha20poly1305::{
    consts::{B0, B1},
    ChaChaPoly1305,
};
use std::{
    io::{Error, ErrorKind, Read, Write},
    vec,
};

pub struct EncryptorMode;
pub struct DecryptorMode;

pub trait EncryptionModule: Write {
    fn finalise(self) -> Result<(), Error>;
}
pub trait DecryptionModule: Read {
    fn finalise(self) -> Result<(), Error>;
}

pub trait EncryptionAlgorithm<T>
where T: Write
{
    type Encryptor: EncryptionModule;

    fn encryptor(&self, writer: T) -> Result<Self::Encryptor, EncryptorInitError>;
}

pub trait DecryptionAlgorithm<T>
where T: Read
{
    type Decryptor: DecryptionModule;

    fn decryptor(&self, reader: T) -> Result<Self::Decryptor, EncryptorInitError>;
}