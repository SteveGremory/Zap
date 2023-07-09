//Internal
use super::{Encryptor, Decryptor, ChaChaPolyEncryptor, AesGcmEncryptor, OpenSslSymmCrypter};

// External
use std::{
    io::{
        Write,
        Read,
        Error,
        ErrorKind
    }
};
use chacha20::ChaChaCore;
use chacha20poly1305::{consts::{B1, B0}, ChaChaPoly1305};
use chacha20poly1305::ChaCha20Poly1305;
use openssl::{
    symm::{Cipher, Crypter, Mode}
};
use aes_gcm::{
    AesGcm,
    aes::{Aes256, cipher::{typenum::{UInt, UTerm}, StreamCipherCoreWrapper}},
    Aes256Gcm,
    AeadCore, 
    KeyInit,
    aead::{
        Aead
    }
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


type null = ();


pub fn aes256cbc_openssl<'a, T>(
    psk: Vec<u8>, 
    iv:Vec<u8>, 
) -> Box<dyn Fn(Result<T, Error>) -> Result<Encryptor<T, Crypter>, Error>>
where T: Write
{
    Box::new( move | x | Ok(
        Encryptor {
            cipher:  Crypter::new(
                Cipher::aes_256_cbc(),
                Mode::Encrypt,
                &psk.clone(),
                None
            ).unwrap(),
            key: psk.clone(),
            nonce: iv.clone(),
            internal_buffer: vec![],
            writer: x?
        }
    ) )
}

pub fn chacha20poly1305<'a, T>(
    psk: Vec<u8>, 
    nonce:Vec<u8>, 
) -> Box<dyn Fn(Result<T, Error>) -> Result<Encryptor<T, ChaChaPolyEncryptor>, Error>>
where T: Write
{
    Box::new( move | x | Ok(
        Encryptor {
            cipher: match ChaCha20Poly1305::new_from_slice(
                    &psk[0..]
                ) {
                    Ok(k) => k,
                    Err(e) => return Err(Error::new(
                        ErrorKind::InvalidData,
                        "Invalid Length"
                    ))
                },
            key: psk.clone(),
            nonce: nonce.clone(),
            internal_buffer: vec![],
            writer: x?
        }
    ) )
}

pub fn aes256<'a, T>(
    psk: Vec<u8>, 
    nonce:Vec<u8>, 
) -> Box<dyn Fn(Result<T, Error>) -> Result<Encryptor<T, AesGcmEncryptor>, Error>>
where T: Write
{
    Box::new( move | x | Ok(
        Encryptor {
            cipher: match Aes256Gcm::new_from_slice(
                    &psk[0..]
                ) {
                    Ok(k) => k,
                    Err(e) => return Err(Error::new(
                        ErrorKind::InvalidData,
                        "Invalid Length"
                    ))
                },
            key: psk.clone(),
            nonce: nonce.clone(),
            internal_buffer: vec![],
            writer: x?
        }
    ) )
}

pub fn encryption_passthrough<'a, T>() -> Box< dyn Fn(Result<T, Error>) -> Result<Encryptor<T, ()>, Error> >
where T: Write
{
    Box::new( move | x | Ok(
        Encryptor {
            cipher:  (),
            key: vec![],
            nonce: vec![],
            internal_buffer: vec![],
            writer: x?
        }
    ) )
}

pub fn aes256_r<'a, T>(
    psk: Vec<u8>, 
    nonce:Vec<u8>, 
) -> Box< dyn Fn(Result<T, Error>) -> Result<Decryptor<T, AesGcmEncryptor>, Error> >
where T: Read
{
    Box::new ( move | x | Ok(
        Decryptor {
            cipher:  Some(
                match Aes256Gcm::new_from_slice(
                    &psk[0..]
                ) {
                    Ok(k) => k,
                    Err(e) => return Err(Error::new(
                        ErrorKind::InvalidData,
                        "Invalid Length"
                    ))
                }
            ),
            key: psk.clone(),
            nonce: nonce.clone(),
            internal_buffer: Vec::new(),
            reader: x?
        }
    ) )
}

pub fn decryption_passthrough<T, U>() -> Box< dyn Fn(Result<T, Error>) -> Result<Decryptor<T, U>, Error> >
where T: Read
{
    Box::new( move | x | Ok(
        Decryptor {
            cipher:  None,
            key: vec![],
            nonce: vec![],
            internal_buffer: Vec::new(),
            reader: x?
        }
    ) )
}