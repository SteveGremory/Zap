use anyhow::anyhow;
use chacha20poly1305::{aead::*, *};
use ed25519_dalek::{Keypair, Signature, Signer};
use rand::{distributions::Alphanumeric, rngs::OsRng, Rng};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
    result::Result,
};

#[derive(Serialize, Deserialize, Debug)]
pub struct Keys {
    pub keypair: Keypair,
    pub signature: Vec<u8>,
    pub nonce: [u8; 24],
}

impl Keys {
    pub fn new() -> Self {
        let mut csprng = OsRng;
        let keypair: Keypair = Keypair::generate(&mut csprng);

        let nonce: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(24)
            .map(char::from)
            .collect();

        Keys {
            keypair,
            signature: vec![0],
            // Safe to unwrap because it's all alphanumeric characters
            nonce: nonce.as_bytes().try_into().unwrap(),
        }
    }

    pub fn save_keypair<P: AsRef<Path>>(&self, filepath: P) {
        // Encode the keypair with bincode and write it to disk.
        let encoded_keypair = bincode::serialize(&self).expect("Failed to serialise keyfile");
        let mut keyfile =
            File::create(filepath).expect("Could not open keyfile, please verify that it exists");
        keyfile
            .write_all(&encoded_keypair)
            .expect("Failed to write the key to disk");
    }

    pub fn from<P: AsRef<Path>>(filepath: P) -> Self {
        let mut filepath = filepath.as_ref().to_owned();

        // Read the keypair, decode it with bincode and return a keypair object
        if !filepath.ends_with(".sfkp") {
            filepath.push(".sfkp");
        };

        let mut keyfile =
            File::open(filepath).expect("Could not open keyfile, please verify that it exists");

        let mut keyfile_contents: Vec<u8> = Vec::new();
        keyfile
            .read_to_end(&mut keyfile_contents)
            .expect("Failed to read the keypair");

        bincode::deserialize(&keyfile_contents[..]).expect("Failed to deseralise the keyfile")
    }

    pub fn sign(&mut self, data: &[u8]) {
        let signature = self.keypair.sign(data);
        self.signature = bincode::serialize(&signature).unwrap();
    }

    pub fn verify(&self, data: &[u8], signature: Vec<u8>) {
        let decoded_signature: Signature = bincode::deserialize(&signature).unwrap();
        let verification = self.keypair.public.verify_strict(data, &decoded_signature);

        // TODO: Do this better
        assert!(verification.is_ok());
    }
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
