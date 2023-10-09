//Internal
use crate::error::EncryptorInitError;

// External
use aes_gcm::{
    aead::{Aead, OsRng},
    KeyInit, AeadCore,
};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use log::info;
use std::{
    io::{Error, ErrorKind, Read, Write},
    vec, marker::PhantomData,
};

use super::{EncryptionAlgorithm, EncryptorMode, DecryptionAlgorithm, DecryptorMode, EncryptionModule, DecryptionModule};

const NONCE_SIZE: usize = 12;

pub struct ChaChaPolyAlgorithm<T> {
    key: T,
}

impl ChaChaPolyAlgorithm<()> {
    pub fn new() -> ChaChaPolyAlgorithm<()> {
        ChaChaPolyAlgorithm {
            key: (),
        }
    }
}

impl Default for ChaChaPolyAlgorithm<()> {
    fn default() -> Self {
        Self::new()
    }
}

impl <T> ChaChaPolyAlgorithm<T> {

    pub fn with_key(self, key: Vec<u8>) -> ChaChaPolyAlgorithm<Vec<u8>> {
        ChaChaPolyAlgorithm {
            key,
        }
    }
}

impl <T> EncryptionAlgorithm<T> for ChaChaPolyAlgorithm<Vec<u8>>
where T: Write
{
    type Encryptor = ChaChaPoly<T, EncryptorMode>;

    fn encryptor(&self, writer: T) -> Result<ChaChaPoly<T, EncryptorMode>, EncryptorInitError> {
        Ok(ChaChaPoly {
            cipher: match ChaCha20Poly1305::new_from_slice(&self.key[0..]) {
                Ok(k) => k,
                Err(e) => return Err(EncryptorInitError::AlgorithmError(format!("ChaChaPoly: {}", e))),
            },
            internal_buffer: vec![],
            io: writer,
            mode: PhantomData
        })
    }
}

impl<T> DecryptionAlgorithm<T> for ChaChaPolyAlgorithm<Vec<u8>>
where T: Read
{
    type Decryptor = ChaChaPoly<T, DecryptorMode>;

    fn decryptor(&self, reader: T) -> Result<ChaChaPoly<T, DecryptorMode>, EncryptorInitError> {
        Ok(ChaChaPoly {
            cipher: match ChaCha20Poly1305::new_from_slice(&self.key[0..]) {
                Ok(k) => k,
                Err(e) => return Err(EncryptorInitError::AlgorithmError(format!("ChaChaPoly: {}", e))),
            },
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
    internal_buffer: Vec<u8>,
    io: T,
    mode: PhantomData<M>,
} 

impl <T> EncryptionModule for ChaChaPoly<T, EncryptorMode> 
where T: Write
{
    fn finalise(mut self) -> Result<(), Error> {
        while !self.internal_buffer.is_empty() {
            let drain_len = std::cmp::min(self.internal_buffer.len(), 8192);

            let buf = self.internal_buffer.drain(..drain_len);

            let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
            
            match self.cipher.encrypt(&nonce, buf.as_slice()) {
                Ok(n) => {
                    info!("Encrypted: {:?}", n.len());
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

impl<T> Write for ChaChaPoly<T, EncryptorMode>
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

            let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

            match self.cipher.encrypt(&nonce, buf.as_slice()) {
                Ok(n) => {
                    info!("Encrypted: {:?}", n.len());
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

impl <T> DecryptionModule for ChaChaPoly<T, DecryptorMode>
where T: Read
{
    fn finalise(self) -> Result<(), Error> {
        Ok(())
    }
}

impl<T> Read for ChaChaPoly<T, DecryptorMode>
where
    T: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        
        let mut raw_buf = vec![0u8; 8192+16+NONCE_SIZE];

        let read_len = self.io.read(&mut raw_buf)?;

        if read_len > 0 {
            let raw_nonce= raw_buf.drain(..NONCE_SIZE).collect::<Vec<u8>>();
            let nonce = Nonce::from_slice(&raw_nonce);

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