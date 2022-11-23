//Internal
use super::{Encryptor, Decryptor};

// External
use std::{
    io::{
        Write,
        Read,
        Error,
    }
};
use openssl::{
    symm::{Cipher, Crypter, Mode}
};

pub fn aes256<'a, T>(
    psk: Vec<u8>, 
    iv:Vec<u8>, 
) -> impl Fn(Result<T, Error>) -> Result<Encryptor<T>, Error>
where T: Write
{
    move | x | Ok(
        Encryptor {
            cipher:  Crypter::new(
                Cipher::aes_256_cbc(),
                Mode::Encrypt,
                &psk.clone(),
                None
            ).unwrap(),
            _key_len: 256,
            blocksize: Cipher::aes_256_cbc().block_size(),
            _iv: iv.clone(),
            internal_buffer: Vec::new(),
            writer: x?
        }
    )
}

pub fn aes256_r<'a, T>(
    psk: Vec<u8>, 
    iv:Vec<u8>, 
) -> impl Fn(Result<T, Error>) -> Result<Decryptor<T>, Error>
where T: Read
{
    move | x | Ok(
        Decryptor {
            cipher:  Crypter::new(
                Cipher::aes_256_cbc(),
                Mode::Decrypt,
                &psk.clone(),
                None
            ).unwrap(),
            _key_len: 256,
            blocksize: Cipher::aes_256_cbc().block_size(),
            _iv: iv.clone(),
            internal_buffer: Vec::new(),
            reader: x?
        }
    )
}