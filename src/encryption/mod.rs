pub mod algorithm;

//Internal
use crate::{internal::return_if_equal, compression::Cleanup};

// External
use rpassword::prompt_password;
use std::{
    io::{
        Write,
        Read,
        Error,
        ErrorKind,
    }, fmt::format, vec, os::linux::raw
};
use openssl::{
    hash::{
        hash,
        MessageDigest
    },
    symm::{
        Cipher,
        encrypt, decrypt, Crypter, Mode
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
    cipher: Crypter,
    _key_len: u64,
    blocksize: usize,
    _iv: Vec<u8>,
    internal_buffer: Vec<u8>,
    writer: T
}

impl<T> Write for Encryptor<T> 
where T: Write
{

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        
        let buf_len = buf.len();
        let mut enc_buf = vec![0u8;buf_len+self.blocksize];

        let len = match self.cipher.update(
            &buf, 
            &mut enc_buf, 
        ) {
            Ok(n) => n,
            Err(e) => return Err(
                Error::new(
                    ErrorKind::Other, 
                    format!("Failed to encrypt: {}", e.to_string()))
            )
        };

        if len > 0 {
            self.writer.write(&enc_buf[0..len])?;
        }
        
        Ok(buf_len)
    }
}

impl<T> Cleanup<T> for Encryptor<T>
where 
T: Write
{
    fn cleanup(mut self) ->  Result<T, Error> {
        let mut enc_buf = vec![0u8;self.blocksize];
        let len = self.cipher.finalize(&mut enc_buf)?;
        dbg!(len);
        self.writer.write(&mut enc_buf)?;
        self.writer.flush()?;
        Ok(self.writer)
    }
}

pub struct Decryptor<T>
where T: Read
{
    cipher: Crypter,
    _key_len: u64,
    blocksize: usize,
    _iv: Vec<u8>,
    internal_buffer: Vec<u8>,
    reader: T
}

impl<T> Read for Decryptor<T> 
where T: Read
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        
        if self.internal_buffer.len() == 0{
            let mut raw_buf = vec![0u8;8192];
            
            let read_len = self.reader.read(&mut raw_buf)?;

            let mut dec_buf = vec![0u8;read_len+self.blocksize];
            
            if read_len > 0 {
                match self.cipher.update(
                    &mut raw_buf[0..read_len],
                    &mut dec_buf
                ) {
                    Ok(l) => {
                        self.internal_buffer.extend_from_slice(&mut dec_buf[0..l]);
                        let mut fin_buf = vec![0u8; 32];
                        if read_len < 8192 {
                            let len = self.cipher.finalize(&mut fin_buf)?;
                            self.internal_buffer.extend_from_slice(&mut fin_buf[0..len]);
                        }
                    },
                    Err(e) => return Err(
                        Error::new(
                            ErrorKind::Other, 
                            format!("Failed to decrypt: {}", e.to_string()))
                    )
                }
            } else {
                return Ok(0);
            }
        }
        let cpy_len = std::cmp::min(buf.len(), self.internal_buffer.len());
        buf[..cpy_len].clone_from_slice(
            self.internal_buffer
            .drain(..cpy_len)
            .as_slice()
        );
        
        Ok(cpy_len)
    }
}

impl<T> Cleanup<T> for Decryptor<T>
where 
T: Read
{
    fn cleanup(mut self) ->  Result<T, Error> {
        //let mut enc_buf = Vec::new();
        //self.cipher.finalize(&mut enc_buf)?;
        Ok(self.reader)
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