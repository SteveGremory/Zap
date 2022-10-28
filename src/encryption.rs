use chacha20poly1305::{
    aead::{Aead, KeyInit},
    Key, XChaCha20Poly1305, XNonce,
};

use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct Keys {
    pub key: Key,
    pub nonce: XNonce,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CryptMode {
    Encrypt,
    Decrypt,
}

/// A custom implementation of `std::io::copy` which encrypts/decrypts the buffer
/// while copying from reader to the writer.
pub fn copy_crypt<R: Read + ?Sized, W: Write + ?Sized>(
    reader: &mut R,
    writer: &mut W,
    keys: Keys,
    mode: CryptMode,
) -> io::Result<usize> {
    const BUFFER_SIZE: usize = 4096;

    let mut vec_buffer: Vec<u8> = vec![0; BUFFER_SIZE];
    let cipher_instance = XChaCha20Poly1305::new(&keys.key);

    let mut final_len = 0;
    let mut encrypted_buffer: Vec<u8>;

    loop {
        let len: usize = reader.read(&mut vec_buffer).expect("Failed to read buffer");

        if len == 0 {
            break;
        }

        // Encrypt or decrypt the buffer
        if mode == CryptMode::Encrypt {
            encrypted_buffer = cipher_instance
                .encrypt(&keys.nonce, &vec_buffer[..len])
                .unwrap();
        } else {
            encrypted_buffer = cipher_instance
                .decrypt(&keys.nonce, &vec_buffer[..len])
                .unwrap();
        }

        final_len += len;
        writer.write_all(&encrypted_buffer)?;

        vec_buffer.clear();
    }

    Ok(final_len)
}
