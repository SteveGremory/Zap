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

/// This file holds all of the functions that return a Writer/Reader
/// for encrypting/decrypting data.
/// Each function should take the arguments necessary to build the struct
/// excluding the internal writer. It should then return a boxed dynamic
/// trait with the signature 'Fn(Result<T, Error>) -> Result<Encryptor<T>, Error>'
/// for encryption and 'Fn(Result<T, Error>) -> Result<Decryptor<T>, Error>'
/// for decryption. 
/// A function can then be bound to the signing and comp/decomp constructors
/// using zap::internal::bind_io_constructors.
/// 
/// When adding encryption methods, there is currently some boilerplate in the lib and bin files.
/// Future versions will work to minimize this.

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