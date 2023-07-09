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
use aes_gcm::{
    AeadCore, 
    KeyInit,
    Nonce,
    aead::{
        Payload,
        Aead, AeadMutInPlace
    }, AesGcm, aes::Aes256
};
use chacha20::{cipher::{StreamCipherCoreWrapper, typenum::{UInt, UTerm}}, ChaChaCore};
use chacha20poly1305::{ChaChaPoly1305, consts::{B1, B0}};
use openssl::symm::{Crypter};
//use chacha20poly1305::{

//};

/// This file holds the structs for building encryptors and decryptors.
/// Currently the are tightly coupled with openssl, aes style cipher structs.
/// Future versions will work to generalise this as much as possible.

pub type AesGcmEncryptor = AesGcm<Aes256, UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>>;
pub type ChaChaPolyEncryptor = ChaChaPoly1305<StreamCipherCoreWrapper<ChaChaCore<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B1>, B0>>>>;
pub type OpenSslSymmCrypter = Crypter;

pub struct Encryptor<T, U>
where T: Write
{
    cipher: U,
    key: Vec<u8>,
    // Temporarily stored as Vec<u8> until it is decided how
    // How the nonce will be stored as in zap metadata
    nonce: Vec<u8>,
    internal_buffer: Vec<u8>,
    writer: T
}


impl<T> Write for Encryptor<T, ()> 
where T: Write
{
    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.writer.write(buf)
    }
}

impl<T> Write for Encryptor<T, OpenSslSymmCrypter> 
where T: Write
{

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Match acts as a passthrough structs when encryption is off.
        // This is a bit hacky and will be updated when the struct is generalised.

        let buf_len = buf.len();
        // This is a very openssl::aes sepcific buffer len.
        // May change in future as more algorithms are added.
        let mut enc_buf = vec![0u8;buf_len+32];
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
}


impl<T> Write for Encryptor<T, ChaChaPolyEncryptor>
where T: Write
{
    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.internal_buffer.extend_from_slice(buf);
        if self.internal_buffer.len() > 8192{
            let enc_buf = match self.cipher.encrypt(
                // As noted in the struct def, this is will be changed
                Nonce::from_slice(&self.nonce),
                /*Payload{
                msg: self.internal_buffer
                .drain(..8192)
                .as_slice(),
                aad: &self.key
                }*/
                self.internal_buffer
                .drain(..8192)
                .as_slice()
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
            self.writer.write(&enc_buf)?;
        }
        // Seeing as we either hold or write the whole buffer and the internal buffer will be written
        // at some point in the future (see 'impl Cleanup for Encryptor') we
        // can report to the outer Writer that we have written the whole buffer.
        Ok(buf.len())
    }
}

/*impl<T> Write for Encryptor<T, AesGcmEncryptor>
where T: Write
{
    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {

        self.internal_buffer.extend_from_slice(buf);
        if self.internal_buffer.len() > 8192{
            let enc_buf = match self.cipher.encrypt(
                // As noted in the struct def, this is will be changed
                Nonce::from_slice(&self.nonce),
                /*Payload{
                msg: self.internal_buffer
                .drain(..8192)
                .as_slice(),
                aad: &self.key
                }*/
                self.internal_buffer
                .drain(..8192)
                .as_slice()
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
            self.writer.write(&enc_buf)?;
        }
        // Seeing as we either hold or write the whole buffer and the internal buffer will be written
        // at some point in the future (see 'impl Cleanup for Encryptor') we
        // can report to the outer Writer that we have written the whole buffer.
        Ok(buf.len())
    }
}*/

impl<T> Write for Encryptor<T, AesGcmEncryptor>
where T: Write
{
    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {

        self.internal_buffer.extend_from_slice(buf);
        /*if self.internal_buffer.len() > 8192{
            let enc_buf = match self.cipher.encrypt(
                // As noted in the struct def, this is will be changed
                Nonce::from_slice(&self.nonce),
                /*Payload{
                msg: self.internal_buffer
                .drain(..8192)
                .as_slice(),
                aad: &self.key
                }*/
                self.internal_buffer
                .drain(..8192)
                .as_slice()
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
            self.writer.write(&enc_buf)?;
        }*/
        // Seeing as we either hold or write the whole buffer and the internal buffer will be written
        // at some point in the future (see 'impl Cleanup for Encryptor') we
        // can report to the outer Writer that we have written the whole buffer.
        Ok(buf.len())
    }
}

impl<T> Cleanup<T> for Encryptor<T, ()>
where T: Write
{
    fn cleanup(mut self) ->  Result<T, Error> {
        
        self.writer.flush()?;
        Ok(self.writer)
    }
}

impl<T> Cleanup<T> for Encryptor<T, Crypter>
where T: Write
{
    fn cleanup(mut self) ->  Result<T, Error> {
        
        let mut enc_buf = vec![0u8;32];
        self.cipher.finalize(&mut enc_buf)?;
        self.writer.write(&mut enc_buf)?;
        
        self.writer.flush()?;
        Ok(self.writer)
    }
}

/*impl<T> Cleanup<T> for Encryptor<T, AesGcmEncryptor>
where T: Write
{
    fn cleanup(mut self) ->  Result<T, Error> {
        // For ciphers that maintain an internal buffer
        // we need to signal to the struct to pad and drain the
        // internal buffer.
        // Currently, as the struct is so openssl::aes coupled, 
        // This will happen if any cipher is provided to the struct.
        // This will change in future implementations.
        while self.internal_buffer.len()>8192{
            let enc_buf = match self.cipher.encrypt(
                // As noted in the struct def, this is will be changed
                Nonce::from_slice(&self.nonce),
                /*Payload{
                    msg: self.internal_buffer
                .drain(..8192)
                .as_slice(),
                aad: &self.key
                }*/
                self.internal_buffer
                .drain(..8192)
                .as_slice()
            ) {
                Ok(n) => {n},
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
            self.writer.write(&enc_buf)?;
        }
        let enc_buf = match self.cipher.encrypt(
            Nonce::from_slice(&self.nonce),
            /*Payload{
                    msg: self.internal_buffer
                .drain(..8192)
                .as_slice(),
                aad: &self.key
                }*/
                self.internal_buffer
                .drain(0..)
                .as_slice()
        ) {
            Ok(n) => n,
            Err(e) => return Err(
                Error::new(
                    ErrorKind::Other, 
                    format!("Failed to encrypt: {}", e.to_string()))
            )
        };

        self.writer.write(&enc_buf)?;
        
        self.writer.flush()?;
        Ok(self.writer)
    }
}*/

impl<T> Cleanup<T> for Encryptor<T, AesGcmEncryptor>
where T: Write
{
    fn cleanup(mut self) ->  Result<T, Error> {
        dbg!("Start encryption");
        dbg!(self.internal_buffer.len());
        let tag = match self.cipher.encrypt_in_place_detached(
            Nonce::from_slice(&self.nonce),
            &self.key,
            &mut self.internal_buffer
        ) {
            Ok(n) => n,
            Err(e) => return Err(
                Error::new(
                    ErrorKind::Other, 
                    format!("Failed to encrypt: {}", e.to_string()))
            )
        };
        dbg!("Finish encryption");

        self.writer.write(&mut self.internal_buffer)?;
        
        self.writer.flush()?;
        Ok(self.writer)
    }
}


impl<T> Cleanup<T> for Encryptor<T, ChaChaPolyEncryptor>
where T: Write
{
    fn cleanup(mut self) ->  Result<T, Error> {
        // For ciphers that maintain an internal buffer
        // we need to signal to the struct to pad and drain the
        // internal buffer.
        // Currently, as the struct is so openssl::aes coupled, 
        // This will happen if any cipher is provided to the struct.
        // This will change in future implementations.
        while self.internal_buffer.len()>8192{
            let enc_buf = match self.cipher.encrypt(
                // As noted in the struct def, this is will be changed
                Nonce::from_slice(&self.nonce),
                /*Payload{
                    msg: self.internal_buffer
                .drain(..8192)
                .as_slice(),
                aad: &self.key
                }*/
                self.internal_buffer
                .drain(..8192)
                .as_slice()
            ) {
                Ok(n) => {n},
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
            self.writer.write(&enc_buf)?;
        }
        let enc_buf = match self.cipher.encrypt(
            Nonce::from_slice(&self.nonce),
            /*Payload{
                    msg: self.internal_buffer
                .drain(..8192)
                .as_slice(),
                aad: &self.key
                }*/
                self.internal_buffer
                .drain(0..)
                .as_slice()
        ) {
            Ok(n) => n,
            Err(e) => return Err(
                Error::new(
                    ErrorKind::Other, 
                    format!("Failed to encrypt: {}", e.to_string()))
            )
        };

        self.writer.write(&enc_buf)?;
        
        self.writer.flush()?;
        Ok(self.writer)
    }
}

pub struct Decryptor<T, U>
where T: Read
{
    cipher: Option<U>,
    key: Vec<u8>,
    nonce: Vec<u8>,
    internal_buffer: Vec<u8>,
    reader: T
}

impl<T, U> Read for Decryptor<T, U> 
where T: Read, U: Aead+AeadCore+KeyInit
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
                    
                    let mut raw_buf = vec![0u8;8208];
                    
                    let read_len = self.reader.read(&mut raw_buf)?;
          
                    if read_len > 0 {
                        
                        match cipher.decrypt(
                            Nonce::from_slice(&self.nonce),
                            &raw_buf[..read_len]
                            /*Payload {
                                msg: &raw_buf[..read_len],
                                aad: &self.key
                            }*/
                        ) {
                            Ok(mut plaintext) => {
                                // May consider changing this so that cipher.update writes
                                // directly to self.internal_buffer. For now though we can 
                                // extend self.internal_buffer from dec_buf.
                                self.internal_buffer.extend_from_slice(&mut plaintext);
                                
                                // todo: need to move this call to finalize in 'impl Cleanup for Decryptor'
                                // as it doesn't make a lot of sense here.
                                // It is here for the interim as this whole struct is read rather than written.
                                // As it is read, we can't force the wrapping writer to take any more of our
                                // internal buffer.
                                // Maybe we can rewrite the compressions writer struct to call read one last
                                // time before finalising, in 'impl Cleanup for Lz4Decoder'.
                            },
                            Err(e) => {return Err(
                                Error::new(
                                    ErrorKind::Other, 
                                    format!("Failed to decrypt: {}", e.to_string()))
                            )}
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

impl<T, U> Cleanup<T> for Decryptor<T, U>
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
