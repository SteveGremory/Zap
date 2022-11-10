pub mod algorithm;

//Internal
use crate::{internal::return_if_equal, compression::Cleanup};

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

pub fn get_password_dec(key_len: usize) -> Result<Vec<u8>, std::io::Error>
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
                    Error::new(
                        ErrorKind::Other,
                        format!("{}", e.to_string())
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

pub struct Encryptor<T>
where T: Write
{
    cipher: Cipher,
    _key_len: u64,
    key: Vec<u8>,
    _iv: Vec<u8>,
    writer: T
}

impl<T> Write for Encryptor<T> 
where T: Write
{

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        //dbg!(buf.len());
        let buf_len = buf.len();
        match encrypt(
            self.cipher, 
            &self.key, 
            None, 
            buf) {
            Ok(mut v) => {
                while !v.is_empty() {
                    let n = self.writer.write(&v)?;

                    if n == 0 {
                        return Ok(0)
                    } else {
                        v = v[n..].to_owned();
                    }
                }
                Ok(buf_len)
            },
            Err(e) => return Err(
                Error::new(
                    ErrorKind::Other, 
                    format!("Encryption failed: {}", e.to_string())
                )
            )
        }
    }
}

impl<T> Cleanup<T> for Encryptor<T>
where 
T: Write
{
    fn cleanup(mut self) ->  Result<T, Error> {
        self.flush()?;
        Ok(self.writer)
    }
}

pub fn encryption_passthrough<T>(input: Result<T, Error>) -> Result<EncryptionPassthrough<T>, Error>
where T: Write
{
    match input {
        Err(e) => Err(e),
        Ok(input) => Ok(
            EncryptionPassthrough{
                inner: input
            }
        )
    }
}

pub struct EncryptionPassthrough<T>
{
    inner: T
}

impl<T> Write for EncryptionPassthrough<T>
where T: Write
{
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }
}

impl<T> Cleanup<T> for EncryptionPassthrough<T>
where T: Write
{
    fn cleanup(mut self) ->  Result<T, Error> {
        self.inner.flush()?;
        Ok(self.inner)
    }
}