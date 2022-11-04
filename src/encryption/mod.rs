pub mod algorithm;

//Internal
use crate::internal::return_if_equal;

// External
use rpassword::prompt_password;
use std::{
    io::{
        Write,
        Error,
        ErrorKind,
    }
};
use openssl::{
    hash::{
        hash,
        MessageDigest
    },
    symm::{
        Cipher,
        encrypt
    }
};

pub fn get_password_enc(key_len: usize) -> Result<Vec<u8>, Error>
{
    convert_pw_to_key(
        return_if_equal(
            prompt_password("Enter a password for encryption: ")?, 
            prompt_password("Repeat encryption password: ")?
        )?,
        key_len
    )
}

pub fn decrypt_directory_pw(key_len: usize) -> Result<Vec<u8>, std::io::Error>
{
    convert_pw_to_key(
        prompt_password(
            "Enter a password for encryption: "
        )?, 
        key_len
    )
}

pub fn convert_pw_to_key(pw: String, len: usize) -> Result<Vec<u8>, Error>
{
    match len {
        256 => {
            match hash(MessageDigest::sha256(), pw.as_bytes()) {
                Ok(digest) => {
                    Ok(digest.to_vec())
                },
                Err(e) => Err(
                    Error::from(
                        ErrorKind::Interrupted
                    )
                )
            }
        },
        _ => Err(
            Error::from(
                ErrorKind::InvalidInput
            )
        )
    }
}

pub struct Encryptor<'a, T>
where T: Write
{
    cipher: Cipher,
    key_len: u64,
    key: &'a [u8],
    iv: &'a [u8],
    writer: T
}

impl<T> Write for Encryptor<'_, T> 
where T: Write
{

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match encrypt(
            self.cipher, 
            self.key, 
            Some(self.iv), 
            buf) {
            Ok(v) => self.writer.write(&v),
            Err(e) => return Err(
                Error::new(
                    ErrorKind::Interrupted, 
                    "Encryption failed."
                )
            )
        }
    }
}