//Internal
use crate::error::EncryptorInitError;

// External
use aes_gcm::{
    aead::{Aead, OsRng},
    KeyInit, AeadCore,
};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use std::{
    io::{Error, ErrorKind, Read, Write},
    vec, marker::PhantomData,
};

use super::{EncryptionAlgorithm, EncryptorMode, DecryptionAlgorithm, DecryptorMode, EncryptionModule, DecryptionModule};

const NONCE_SIZE: usize = 24;

pub struct XChaChaPolyAlgorithm<T> {
    key: T,
}

impl XChaChaPolyAlgorithm<()> {
    pub fn new() -> XChaChaPolyAlgorithm<()> {
        XChaChaPolyAlgorithm {
            key: (),
        }
    }
}

impl Default for XChaChaPolyAlgorithm<()> {
    fn default() -> Self {
        Self::new()
    }
}

impl <T> XChaChaPolyAlgorithm<T> {

    pub fn with_key(self, key: Vec<u8>) -> XChaChaPolyAlgorithm<Vec<u8>> {
        XChaChaPolyAlgorithm {
            key,
        }
    }
}

impl <T> EncryptionAlgorithm<T> for XChaChaPolyAlgorithm<Vec<u8>>
where T: Write
{
    type Encryptor = XChaChaPoly<T, EncryptorMode>;

    fn encryptor(&self, writer: T) -> Result<XChaChaPoly<T, EncryptorMode>, EncryptorInitError> {
        Ok(XChaChaPoly {
            cipher: match XChaCha20Poly1305::new_from_slice(&self.key[0..]) {
                Ok(k) => k,
                Err(e) => return Err(EncryptorInitError::AlgorithmError(format!("XChaChaPoly: {}", e))),
            },
            internal_buffer: vec![],
            io: writer,
            mode: PhantomData
        })
    }
}

impl<T> DecryptionAlgorithm<T> for XChaChaPolyAlgorithm<Vec<u8>>
where T: Read
{
    type Decryptor = XChaChaPoly<T, DecryptorMode>;

    fn decryptor(&self, reader: T) -> Result<XChaChaPoly<T, DecryptorMode>, EncryptorInitError> {
        Ok(XChaChaPoly {
            cipher: match XChaCha20Poly1305::new_from_slice(&self.key[0..]) {
                Ok(k) => k,
                Err(e) => return Err(EncryptorInitError::AlgorithmError(format!("XChaChaPoly: {}", e))),
            },
            internal_buffer: vec![],
            io: reader,
            mode: PhantomData
        })
    }
}

pub struct XChaChaPoly<T, M> {
    cipher: XChaCha20Poly1305,
    // Temporarily stored as Vec<u8> until it is decided how
    // How the nonce will be stored as in zap metadata
    internal_buffer: Vec<u8>,
    io: T,
    mode: PhantomData<M>,
} 

impl <T> EncryptionModule for XChaChaPoly<T, EncryptorMode> 
where T: Write
{
    fn finalise(mut self) -> Result<(), Error> {
        while !self.internal_buffer.is_empty() {
            let drain_len = std::cmp::min(self.internal_buffer.len(), 8192);

            let buf = self.internal_buffer.drain(..drain_len);

            let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
            
            match self.cipher.encrypt(&nonce, buf.as_slice()) {
                Ok(n) => {
                    self.io.write_all(&nonce)?;
                    self.io.write_all(&n)?;
                }
                Err(e) => return Err(Error::new(
                    ErrorKind::Other,
                    format!("Failed to encrypt: {}", e),
                )),
            }
        }

        self.io.flush()?;

        Ok(())
    }
}

impl<T> Write for XChaChaPoly<T, EncryptorMode>
where
    T: Write,
{
    fn flush(&mut self) -> std::io::Result<()> {
        self.io.flush()
    }

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
 
        /*
            Payload for each block is written as:
            [ nonce ][ ciphertext ][ tag ]
            [ 24    ][ 8192       ][ 16  ] (Bytes)
        */

        self.internal_buffer.extend_from_slice(buf);

        while self.internal_buffer.len() > 8192 {
            let buf = self.internal_buffer.drain(..8192);

            let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

            match self.cipher.encrypt(&nonce, buf.as_slice()) {
                Ok(n) => {
                    self.io.write_all(&nonce)?;
                    self.io.write_all(&n)?;
                }
                Err(e) => return Err(Error::new(
                    ErrorKind::Other,
                    format!("Failed to encrypt: {}", e),
                )),
            }
        }

        Ok(buf.len())
    }
}

impl <T> DecryptionModule for XChaChaPoly<T, DecryptorMode>
where T: Read
{
    fn finalise(self) -> Result<(), Error> {
        Ok(())
    }
}

impl<T> Read for XChaChaPoly<T, DecryptorMode>
where
    T: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        
        let mut raw_buf = vec![0u8; 8192+16+NONCE_SIZE];

        let read_len = self.io.read(&mut raw_buf)?;

        if read_len > 0 {
            let raw_nonce= raw_buf.drain(..NONCE_SIZE).collect::<Vec<u8>>();
            let nonce = XNonce::from_slice(&raw_nonce);

            match self.cipher.decrypt(
                nonce,
                &raw_buf[..(read_len-NONCE_SIZE)], /* Payload {
                                          msg: &raw_buf[..read_len],
                                          aad: &self.key
                                      }*/
            ) {
                Ok(plaintext) => {
                    // May consider changing this so that cipher.update writes
                    // directly to self.internal_buffer. For now though we can
                    // extend self.internal_buffer from dec_buf.
                    self.internal_buffer.extend_from_slice(&plaintext);
                },
                Err(e) => {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("Failed to decrypt: {}", e),
                    ))
                }
            }
        }

        // Copy n bytes where n is the lesser of buf and internal_buf
        // The copy is super jank but that will hopefully change when
        // slice.take() take comes out of nightly.
        let cpy_len = std::cmp::min(buf.len(), self.internal_buffer.len());
        buf[..cpy_len].clone_from_slice(self.internal_buffer.drain(..cpy_len).as_slice());

        Ok(cpy_len)
    }
}