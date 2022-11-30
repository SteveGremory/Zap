pub mod algorithm;

//Internal
use crate::internal::Cleanup;

// External
use std::{
    io::{
        Write,
        Read,
        Error,
        ErrorKind,
    }, vec
};
use openssl::{
    symm::{
        Crypter
    }
};



pub struct Encryptor<T>
where T: Write
{
    cipher: Option<Crypter>,
    _key_len: u64,
    blocksize: usize,
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
        match &mut self.cipher {
            Some(cipher) => {
                let buf_len = buf.len();
                let mut enc_buf = vec![0u8;buf_len+self.blocksize];
                let len = match cipher.update(
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
            None => {
                self.writer.write(buf)
            }
        }

       
    }
}

impl<T> Cleanup<T> for Encryptor<T>
where 
T: Write
{
    fn cleanup(mut self) ->  Result<T, Error> {
        
        if let Some(cipher) = &mut self.cipher {
            let mut enc_buf = vec![0u8;self.blocksize];
            cipher.finalize(&mut enc_buf)?;
            self.writer.write(&mut enc_buf)?;
        }
        
        self.writer.flush()?;
        Ok(self.writer)
    }
}

pub struct Decryptor<T>
where T: Read
{
    cipher: Option<Crypter>,
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
        match &mut self.cipher {
            Some(cipher) => {
                if self.internal_buffer.len() == 0{
                    let mut raw_buf = vec![0u8;8192];
                    
                    let read_len = self.reader.read(&mut raw_buf)?;
        
                    let mut dec_buf = vec![0u8;read_len+self.blocksize];
                    
                    if read_len > 0 {
                        match cipher.update(
                            &mut raw_buf[0..read_len],
                            &mut dec_buf
                        ) {
                            Ok(l) => {
                                self.internal_buffer.extend_from_slice(&mut dec_buf[0..l]);
                                let mut fin_buf = vec![0u8; 32];
                                if read_len < 8192 {
                                    let len = cipher.finalize(&mut fin_buf)?;
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
            },
            None => {
                self.reader.read(buf)
            }
        }
        
    }
}

impl<T> Cleanup<T> for Decryptor<T>
where 
T: Read
{
    fn cleanup(self) ->  Result<T, Error> {
        Ok(self.reader)
    }
}
