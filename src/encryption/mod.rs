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

/// This file holds the structs for building encryptors and decryptors.
/// Currently the are tightly coupled with openssl, aes style cipher structs.
/// Future versions will work to generalise this as much as possible.

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
        // Match acts as a passthrough structs when encryption is off.
        // This is a bit hacky and will be updated when the struct is generalised.
        match &mut self.cipher {
            Some(cipher) => {
                let buf_len = buf.len();
                // This is a very openssl::aes sepcific buffer len.
                // May change in future as more algorithms are added.
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
                // This is also implementation specific. 
                // As the aes is a block cipher is manages and internal buffer 
                // and when the buffer reaches a length greater than the blocksize
                // it will consume a multiple of it's blocksize of bytes and encrypt
                // them to enc_buf
                if len > 0 {
                    self.writer.write(&enc_buf[0..len])?;
                }
                // Seeing as we either hold or write the whole buffer and the internal buffer will be written
                // at some point in the future (see 'impl Cleanup for Encryptor') we
                // can report to the outer Writer that we have written the whole buffer.
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
        // For ciphers that maintain an internal buffer
        // we need to signal to the struct to pad and drain the
        // internal buffer.
        // Currently, as the struct is so openssl::aes coupled, 
        // This will happen if any cipher is provided to the struct.
        // This will change in future implementations.
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
        // Match acts as a passthrough structs when encryption is off.
        // This is a bit hacky and will be updated when the struct is generalised.
        match &mut self.cipher {
            Some(cipher) => {
                // If the buffer is empty, fill it with contents from decrypt(read())
                // Then fill &mut buf with as much of the internal buffer as possible.
                if self.internal_buffer.len() == 0{
                    // 8kB is used as it is the buffer size of std::fs::copy
                    // but this is otherwise arbitrary.
                    let mut raw_buf = vec![0u8;8192];
                    
                    let read_len = self.reader.read(&mut raw_buf)?;
                    // Again, this is a very openssl::aes sepcific buffer len.
                    // May change in future as more algorithms are added.
                    let mut dec_buf = vec![0u8;read_len+self.blocksize];
                    
                    if read_len > 0 {
                        match cipher.update(
                            &mut raw_buf[0..read_len],
                            &mut dec_buf
                        ) {
                            Ok(l) => {
                                // May consider changing this so that cipher.update writes
                                // directly to self.internal_buffer. For now though we can 
                                // extend self.internal_buffer from dec_buf.
                                self.internal_buffer.extend_from_slice(&mut dec_buf[0..l]);
                                
                                // todo: need to move this call to finalize in 'impl Cleanup for Decryptor'
                                // as it doesn't make a lot of sense here.
                                // It is here for the interim as this whole struct is read rather than written.
                                // As it is read, we can't force the wrapping writer to take any more of our
                                // internal buffer.
                                // Maybe we can rewrite the compressions writer struct to call read one last
                                // time before finalising, in 'impl Cleanup for Lz4Decoder'.
                                if read_len < 8192 {
                                    let mut fin_buf = vec![0u8; 32];
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
                // Copy n bytes where n is the lesser of buf and internal_buf
                // The copy is super jank but that will hopefully change when
                // slice.take() take comes out of nightly.
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
    /* 
    fn cleanup(mut self) ->  Result<T, Error> {
        if let Some(mut cipher) = self.cipher {
            let mut fin_buf = vec![0u8; 8192];
            let len = cipher.finalize(&mut fin_buf)?;
            self.internal_buffer.extend_from_slice(&mut fin_buf[0..len]);
        }
        Ok(self.reader)
    }
    */
}
