//Internal
use crate::error::EncryptorInitError;

// External
use aes_gcm::{
    aead::Aead,
    KeyInit, Nonce,
};
use chacha20poly1305::ChaCha20Poly1305;
use std::{
    io::{Error, ErrorKind, Read, Write},
    vec, marker::PhantomData,
};

use super::{EncryptionAlgorithm, EncryptorMode, DecryptionAlgorithm, DecryptorMode, Encrypt, Decrypt, Encryptor};

pub struct ChaChaPolyAlgorithm<T, U> {
    key: T,
    // Temporarily stored as Vec<u8> until it is decided how
    // How the nonce will be stored as in zap metadata
    nonce: U,
}

impl ChaChaPolyAlgorithm<(), ()> {
    pub fn new() -> ChaChaPolyAlgorithm<(), ()> {
        ChaChaPolyAlgorithm {
            key: (),
            nonce: (),
        }
    }
}

impl Default for ChaChaPolyAlgorithm<(), ()> {
    fn default() -> Self {
        Self::new()
    }
}

impl <T, U> ChaChaPolyAlgorithm<T, U> {

    pub fn with_key(self, key: Vec<u8>) -> ChaChaPolyAlgorithm<Vec<u8>, U> {
        ChaChaPolyAlgorithm {
            key,
            nonce: self.nonce,
        }
    }

    pub fn with_nonce(self, nonce: Vec<u8>) -> ChaChaPolyAlgorithm<T, Vec<u8>> {
        ChaChaPolyAlgorithm { 
            key: self.key,
            nonce,
        }
    }
}

impl <T> EncryptionAlgorithm<T> for ChaChaPolyAlgorithm<Vec<u8>, Vec<u8>>
where T: Write
{
    type Encryptor = ChaChaPoly<T, EncryptorMode>;

    fn encryptor(&self, writer: T) -> Result<ChaChaPoly<T, EncryptorMode>, EncryptorInitError> {
        Ok(ChaChaPoly {
            cipher: match ChaCha20Poly1305::new_from_slice(&self.key[0..]) {
                Ok(k) => k,
                Err(e) => return Err(EncryptorInitError::AlgorithmError(format!("ChaChaPoly: {}", e))),
            },
            nonce: self.nonce.clone(),
            internal_buffer: vec![],
            io: writer,
            mode: PhantomData
        })
    }
}

impl<T> DecryptionAlgorithm<T> for ChaChaPolyAlgorithm<Vec<u8>, Vec<u8>>
where T: Read
{
    type Decryptor = ChaChaPoly<T, DecryptorMode>;

    fn decryptor(&self, reader: T) -> Result<ChaChaPoly<T, DecryptorMode>, EncryptorInitError> {
        Ok(ChaChaPoly {
            cipher: match ChaCha20Poly1305::new_from_slice(&self.key[0..]) {
                Ok(k) => k,
                Err(e) => return Err(EncryptorInitError::AlgorithmError(format!("ChaChaPoly: {}", e))),
            },
            nonce: self.nonce.clone(),
            internal_buffer: vec![],
            io: reader,
            mode: PhantomData
        })
    }
}

pub struct ChaChaPoly<T, M> {
    cipher: ChaCha20Poly1305,
    // Temporarily stored as Vec<u8> until it is decided how
    // How the nonce will be stored as in zap metadata
    nonce: Vec<u8>,
    internal_buffer: Vec<u8>,
    io: T,
    mode: PhantomData<M>
} 

impl<T> ChaChaPoly<T, EncryptorMode>
where
    T: Write 
{
    fn dump_buffer(&mut self) -> Result<Vec<u8>, Error> {
        let len = std::cmp::min(8192, self.internal_buffer.len());

        match self.cipher.encrypt(
            // As noted in the struct def, this is will be changed
            Nonce::from_slice(&self.nonce),
            /*Payload{
            msg: self.internal_buffer
            .drain(..8192)
            .as_slice(),
            aad: &self.key
            }*/
            self.internal_buffer.drain(..len).as_slice(),
        ) {
            Ok(n) => Ok(n),
            Err(e) => {
                Err(Error::new(
                    ErrorKind::Other,
                    format!("Failed to encrypt: {}", e),
                ))
            }
        }
    }

}

impl <T> Encrypt for ChaChaPoly<T, EncryptorMode> 
where T: Write
{
    fn finalise(mut self) -> Result<(), Error> {
        let buff = self.dump_buffer()?;
        self.io.write_all(buff.as_slice())?;
        self.io.flush()?;
        Ok(())
    }
}

impl<T> Write for ChaChaPoly<T, EncryptorMode>
where
    T: Write,
{
    fn flush(&mut self) -> std::io::Result<()> {
        self.io.flush()
    }

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        println!("Dump buffer enc: {:?}", buf);

        self.internal_buffer.extend_from_slice(buf);

        println!("Internal buffer: {:?}", self.internal_buffer.len());

        if self.internal_buffer.len() > 8192 {
            println!("Encrypting: {:?}", self.internal_buffer.len());

            let enc_buf = self.dump_buffer()?;
            // This is also implementation specific.
            // As the aes is a block cipher is manages and internal buffer
            // and when the buffer reaches a length greater than the blocksize
            // it will consume a multiple of it's blocksize of bytes and encrypt
            // them to enc_buf
            self.io.write_all(&enc_buf)?;
        }
        // Seeing as we either hold or write the whole buffer and the internal buffer will be written
        // at some point in the future (see 'impl Cleanup for Encryptor') we
        // can report to the outer Writer that we have written the whole buffer.
        Ok(buf.len())
    }
}

impl <T> Decrypt for ChaChaPoly<T, DecryptorMode>
where T: Read
{
    fn finalise(self) -> Result<(), Error> {
        //self.io.flush()?;
        Ok(())
    }
}

impl<T> Read for ChaChaPoly<T, DecryptorMode>
where
    T: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        unimplemented!()
    }
}


impl<T> Write for Encryptor<T, ()>
where
    T: Write,
{
    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.writer.write(buf)
    }
}