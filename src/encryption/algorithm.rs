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

pub fn aes256<'a, T>(
    psk: Vec<u8>, 
    iv:Vec<u8>, 
) -> impl Fn(Result<T, Error>) -> Result<Encryptor<T>, Error>
where T: Write
{
    move | x | Ok(
        Encryptor {
            cipher: Cipher::aes_256_cbc(),
            _key_len: 256,
            key: psk.clone(),
            _iv: iv.clone(),
            writer: x?
        }
    )
}
