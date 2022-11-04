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