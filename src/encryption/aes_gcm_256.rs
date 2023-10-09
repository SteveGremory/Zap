use std::{
    io::{Error, ErrorKind, Read, Write},
    marker::PhantomData, os::linux::raw,
};

// External
use aes_gcm::{
    aead::{Aead, AeadMutInPlace, OsRng, Nonce},
    aes::Aes256,
    AeadCore, AesGcm, KeyInit, Aes256Gcm,
};
use log::info;

use crate::error::EncryptorInitError;

use super::{DecryptionModule, DecryptorMode, EncryptionModule, EncryptorMode, EncryptionAlgorithm, DecryptionAlgorithm};

const NONCE_SIZE: usize = 12;

pub struct AesGcmAlgorithm<T, V> {
    key: T,
    // Temporarily stored as Vec<u8> until it is decided how
    // How the nonce will be stored as in zap metadata
    tag: V
}

impl AesGcmAlgorithm<(), ()> {
    pub fn new() -> AesGcmAlgorithm<(), ()> {
        AesGcmAlgorithm {
            key: (),
            tag: (),
        }
    }
}

impl Default for AesGcmAlgorithm<(), ()> {
    fn default() -> Self {
        Self::new()
    }
}

impl <T, V> AesGcmAlgorithm<T, V> {
    pub fn with_key(self, key: Vec<u8>) -> AesGcmAlgorithm<Vec<u8>, V> {
        AesGcmAlgorithm {
            key,
            tag: self.tag,
        }
    }

    pub fn with_tag(self, tag: Vec<u8>) -> AesGcmAlgorithm<T, Vec<u8>> {
        AesGcmAlgorithm {
            key: self.key,
            tag,
        }
    }
}

impl <T> EncryptionAlgorithm<T> for AesGcmAlgorithm<Vec<u8>, ()>
where T: Write
{
    type Encryptor = AesGcmEncryptor<T, EncryptorMode>;

    fn encryptor(&self, io: T) -> Result<Self::Encryptor, EncryptorInitError> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        Ok(
            AesGcmEncryptor {
                cipher: match Aes256Gcm::new_from_slice(&self.key[0..]) {
                    Ok(k) => k,
                    Err(e) => return Err(EncryptorInitError::AlgorithmError(format!("AesGcm: {}", e))),
                },
                nonce,
                tag: None,
                internal_buffer: vec![],
                io,
                mode: PhantomData
            }
        )
    }
}

impl<T> DecryptionAlgorithm<T> for AesGcmAlgorithm<Vec<u8>, ()>
where T: Read
{
    type Decryptor = AesGcmEncryptor<T, DecryptorMode>;

    fn decryptor(&self, io: T) -> Result<Self::Decryptor, EncryptorInitError> {
        Ok(
            AesGcmEncryptor {
                cipher: match Aes256Gcm::new_from_slice(&self.key[0..]) {
                    Ok(k) => k,
                    Err(e) => return Err(EncryptorInitError::AlgorithmError(format!("AesGcm: {}", e))),
                },
                nonce: Nonce::<Aes256Gcm>::default(),
                tag: None,
                internal_buffer: vec![],
                io,
                mode: PhantomData
            }
        )
    }
}

pub struct AesGcmEncryptor<T, M> {
    cipher: Aes256Gcm,
    nonce: Nonce<Aes256Gcm>,
    tag: Option<Vec<u8>>,
    internal_buffer: Vec<u8>,
    io: T,
    mode: PhantomData<M>,
}

impl <T, M> AesGcmEncryptor<T, M> {
    fn _increment_nonce(nonce: Nonce<Aes256Gcm>) -> Nonce<Aes256Gcm> {
        // Originally intended to use an incremented nonce, to avoid the collision problem
        // as noted in https://docs.rs/aes-gcm/latest/aes_gcm/trait.AeadCore.html#provided-methods
        // and https://csrc.nist.gov/publications/detail/sp/800-38d/final where the max number of 
        // random nonces is 2^32. However, this would require using a mutex to share the nonce
        // between threads, which is not ideal. Instead, we will use a random nonce for each
        // block of data, and use a high enough block size to avoid collisions.
        //
        // With that being said, XChaCha20Poly1305 is a better choice for this use case, as it
        // allows for a 192-bit nonce, which is much less likely to collide.

        let mut new_nonce = nonce;
        let mut i = 0;

        while i < new_nonce.len() && {
            new_nonce[i] = new_nonce[i].wrapping_add(1);
            new_nonce[i] == 0
        } {
            i += 1;
        }

        new_nonce
    }
}

impl<T> EncryptionModule for AesGcmEncryptor<T, EncryptorMode>
where
    T: Write,
{
    fn finalise(mut self) -> Result<(), std::io::Error> {

        while !self.internal_buffer.is_empty() {
            let drain_len = std::cmp::min(self.internal_buffer.len(), 8192);

            let buf = self.internal_buffer.drain(..drain_len);

            self.nonce = Aes256Gcm::generate_nonce(&mut OsRng);
            
            match self.cipher.encrypt(&self.nonce, buf.as_slice()) {
                Ok(n) => {
                    info!("Encrypted: {:?}", n.len());
                    self.io.write_all(self.nonce.as_slice())?;
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

impl<T> Write for AesGcmEncryptor<T, EncryptorMode>
where
    T: Write,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {

        /*
            Payload for each block is written as:
            [ nonce ][ ciphertext ][ tag ]
            [ 12    ][ 8192       ][ 16  ] (Bytes)
        */

        self.internal_buffer.extend_from_slice(buf);

        while self.internal_buffer.len() > 8192 {
            let buf = self.internal_buffer.drain(..8192);

            self.nonce = Aes256Gcm::generate_nonce(&mut OsRng);

            match self.cipher.encrypt(&self.nonce, buf.as_slice()) {
                Ok(n) => {
                    info!("Encrypted: {:?}", n.len());
                    self.io.write_all(self.nonce.as_slice())?;
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

    fn flush(&mut self) -> std::io::Result<()> {
        self.io.flush()
    }
}

impl<T> DecryptionModule for AesGcmEncryptor<T, DecryptorMode>
where
    T: Read,
{
    fn finalise(self) -> Result<(), Error> {
        Ok(())
    }
}

impl<T> Read for AesGcmEncryptor<T, DecryptorMode>
where
    T: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {

        let mut raw_buf = vec![0u8; 8192+16+NONCE_SIZE];

        let read_len = self.io.read(&mut raw_buf)?;

        if read_len > 0 {
            let raw_nonce= raw_buf.drain(..12).collect::<Vec<u8>>();
            let nonce = Nonce::<Aes256Gcm>::from_slice(&raw_nonce);

            match self.cipher.decrypt(
                nonce,
                &raw_buf[..(read_len-12)], /* Payload {
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
