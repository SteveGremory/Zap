use chacha20poly1305::{aead::*, *};
use std::io;
use std::io::Write;
use std::{fs::File, io::Read, path::Path};
use walkdir::WalkDir;

pub fn create_combined_file(
    folder_path: &String,
    file_path: &String,
    key: &[u8; 32],
    nonce: &[u8; 19],
) {
    // Walk the directory and find all the files
    for entry in WalkDir::new(folder_path) {
        let entry = entry.unwrap();
        let entry_path = entry.path();

        if Path::new(entry_path).is_dir() {
            continue;
        }

        let mut file_handle = File::open(entry_path).expect("Failed to open the file.");

        let aead = XChaCha20Poly1305::new(key.as_ref().into());
        let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());

        const BUFFER_LEN: usize = 6553600;
        let mut buffer = [0u8; BUFFER_LEN];

        let mut dist_file = File::create(file_path).unwrap();

        loop {
            let read_count = file_handle.read(&mut buffer).unwrap();

            if read_count == BUFFER_LEN {
                let ciphertext = stream_encryptor
                    .encrypt_next(buffer.as_slice())
                    .map_err(|err| println!("Encrypting large file: {}", err))
                    .unwrap();

                dist_file.write_all(&ciphertext).unwrap();
            } else {
                let ciphertext = stream_encryptor
                    .encrypt_last(&buffer[..read_count])
                    .map_err(|err| println!("Encrypting large file: {}", err))
                    .unwrap();

                dist_file.write_all(&ciphertext).unwrap();
                break;
            }
        }
    }
}

pub fn read_combined_file(file_path: &String) {}
