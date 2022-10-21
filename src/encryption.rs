pub mod small_files {

    use anyhow::anyhow;
    use chacha20poly1305::{aead::*, *};
    use std::fs;
    use std::result::Result;

    fn encrypt(
        filepath: &str,
        dist: &str,
        key: &[u8; 32],
        nonce: &[u8; 24],
    ) -> Result<(), anyhow::Error> {
        let cipher = XChaCha20Poly1305::new(key.into());

        let file_data = fs::read(filepath)?;

        let encrypted_file = cipher
            .encrypt(nonce.into(), file_data.as_ref())
            .map_err(|err| anyhow!("Encrypting small file: {}", err))?;

        fs::write(&dist, encrypted_file)?;

        Ok(())
    }

    fn decrypt(
        encrypted_file_path: &str,
        dist: &str,
        key: &[u8; 32],
        nonce: &[u8; 24],
    ) -> Result<(), anyhow::Error> {
        let cipher = XChaCha20Poly1305::new(key.into());

        let file_data = fs::read(encrypted_file_path)?;

        let decrypted_file = cipher
            .decrypt(nonce.into(), file_data.as_ref())
            .map_err(|err| anyhow!("Decrypting small file: {}", err))?;

        fs::write(&dist, decrypted_file)?;

        Ok(())
    }
}

pub mod large_files {

    use anyhow::anyhow;
    use chacha20poly1305::{aead::*, *};
    use std::fs::File;
    use std::io::{Read, Write};
    use std::result::Result;

    fn encrypt(
        source_file_path: &str,
        dist_file_path: &str,
        key: &[u8; 32],
        nonce: &[u8; 19],
    ) -> Result<(), anyhow::Error> {
        let aead = XChaCha20Poly1305::new(key.as_ref().into());
        let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());
        const BUFFER_LEN: usize = 500;
        let mut buffer = [0u8; BUFFER_LEN];

        let mut source_file = File::open(source_file_path)?;
        let mut dist_file = File::create(dist_file_path)?;
        loop {
            let read_count = source_file.read(&mut buffer)?;

            if read_count == BUFFER_LEN {
                let ciphertext = stream_encryptor
                    .encrypt_next(buffer.as_slice())
                    .map_err(|err| anyhow!("Encrypting large file: {}", err))?;
                dist_file.write(&ciphertext)?;
            } else {
                let ciphertext = stream_encryptor
                    .encrypt_last(&buffer[..read_count])
                    .map_err(|err| anyhow!("Encrypting large file: {}", err))?;
                dist_file.write(&ciphertext)?;
                break;
            }
        }

        Ok(())
    }

    fn decrypt(
        encrypted_file_path: &str,
        dist: &str,
        key: &[u8; 32],
        nonce: &[u8; 19],
    ) -> Result<(), anyhow::Error> {
        let aead = XChaCha20Poly1305::new(key.as_ref().into());
        let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());
        const BUFFER_LEN: usize = 500 + 16;
        let mut buffer = [0u8; BUFFER_LEN];

        let mut encrypted_file = File::open(encrypted_file_path)?;
        let mut dist_file = File::create(dist)?;
        loop {
            let read_count = encrypted_file.read(&mut buffer)?;

            if read_count == BUFFER_LEN {
                let plaintext = stream_decryptor
                    .decrypt_next(buffer.as_slice())
                    .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
                dist_file.write(&plaintext)?;
            } else if read_count == 0 {
                break;
            } else {
                let plaintext = stream_decryptor
                    .decrypt_last(&buffer[..read_count])
                    .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
                dist_file.write(&plaintext)?;
                break;
            }
        }

        Ok(())
    }
}
