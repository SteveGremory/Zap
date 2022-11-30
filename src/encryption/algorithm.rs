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
) -> Box<dyn Fn(Result<T, Error>) -> Result<Encryptor<T>, Error>>
where T: Write
{
    Box::new( move | x | Ok(
        Encryptor {
            cipher:  Some(Crypter::new(
                Cipher::aes_256_cbc(),
                Mode::Encrypt,
                &psk.clone(),
                None
            ).unwrap()),
            _key_len: 256,
            blocksize: Cipher::aes_256_cbc().block_size(),
            _iv: iv.clone(),
            writer: x?
        }
    ) )
}

pub fn encryption_passthrough<'a, T>() -> Box< dyn Fn(Result<T, Error>) -> Result<Encryptor<T>, Error> >
where T: Write
{
    Box::new( move | x | Ok(
        Encryptor {
            cipher:  None,
            _key_len: 256,
            blocksize: 32,
            _iv: vec![],
            writer: x?
        }
    ) )
}

pub fn aes256_r<'a, T>(
    psk: Vec<u8>, 
    iv:Vec<u8>, 
) -> Box< dyn Fn(Result<T, Error>) -> Result<Decryptor<T>, Error> >
where T: Read
{
    Box::new ( move | x | Ok(
        Decryptor {
            cipher:  Some(Crypter::new(
                Cipher::aes_256_cbc(),
                Mode::Decrypt,
                &psk.clone(),
                None
            ).unwrap()),
            _key_len: 256,
            blocksize: Cipher::aes_256_cbc().block_size(),
            _iv: iv.clone(),
            internal_buffer: Vec::new(),
            reader: x?
        }
    ) )
}

pub fn decryption_passthrough<T>() -> Box< dyn Fn(Result<T, Error>) -> Result<Decryptor<T>, Error> >
where T: Read
{
    Box::new( move | x | Ok(
        Decryptor {
            cipher:  None,
            _key_len: 256,
            blocksize: 32,
            _iv: vec![],
            internal_buffer: Vec::new(),
            reader: x?
        }
    ) )
}