use anyhow::anyhow;
use chacha20poly1305::{aead::*, *};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Write},
    path::PathBuf,
};

use std::result::Result;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Keypair {
    pub key: [u8; 32],
    pub nonce: [u8; 24],
}

pub fn encrypt(
    file_data: Vec<u8>,
    key: &[u8; 32],
    nonce: &[u8; 24],
) -> Result<Vec<u8>, anyhow::Error> {
    let cipher = XChaCha20Poly1305::new(key.into());

    let encrypted_file = cipher
        .encrypt(nonce.into(), file_data.as_ref())
        .map_err(|err| anyhow!("Encrypting small file: {}", err))?;

    Ok(encrypted_file)
}

pub fn decrypt(
    file_data: Vec<u8>,
    key: &[u8; 32],
    nonce: &[u8; 24],
) -> Result<Vec<u8>, anyhow::Error> {
    let cipher = XChaCha20Poly1305::new(key.into());

    let decrypted_file = cipher
        .decrypt(nonce.into(), file_data.as_ref())
        .map_err(|err| anyhow!("Decrypting small file: {}", err))?;

    Ok(decrypted_file)
}

impl Keypair {
    pub fn new() -> Self {
        // For now, just make the key and the nonce a bunch of random characters.
        let random_string: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(24)
            .map(char::from)
            .collect();

        let nonce: [u8; 24] = random_string
            .as_bytes()
            .try_into()
            .expect("Failed to initialise the nonce");
        let key: [u8; 32] = blake3::hash(random_string.as_bytes())
            .try_into()
            .expect("Failed to initalise the key");

        Keypair {
            key: key,
            nonce: nonce,
        }
    }

    pub fn save_keypair(&self, filepath: PathBuf) {
        // Encode the keypair with bincode and write it to disk.
        let encoded_keypair = bincode::serialize(&self).expect("Failed to serialise keyfile");
        let mut keyfile =
            File::create(filepath).expect("Could not open keyfile, please verify that it exists");
        keyfile
            .write_all(&encoded_keypair)
            .expect("Failed to write the key to disk");
    }

    pub fn from(filepath: PathBuf) -> Self {
        // Read the keypair, decode it with bincode and return a keypair object
        let mut keyfile =
            File::open(filepath).expect("Could not open keyfile, please verify that it exists");

        let mut keyfile_contents: Vec<u8> = Vec::new();
        keyfile
            .read_to_end(&mut keyfile_contents)
            .expect("Failed to read the keypair");

        let decoded: Keypair =
            bincode::deserialize(&keyfile_contents[..]).expect("Failed to deseralise the keyfile");

        return decoded;
    }
}
