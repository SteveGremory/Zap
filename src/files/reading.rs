use crate::encryption::*;
use crate::files::*;
use chacha20poly1305::Key;
use chacha20poly1305::{
    aead::{AeadCore, AeadInPlace, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};

use lz4_flex::{compress_prepend_size, decompress_size_prepended};
use memmap2::Mmap;
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};
use tokio::{io::AsyncWriteExt, task};
use walkdir::WalkDir;

pub fn create_combined_file(folder_path: &String, file_path: &String, opt_keys: Option<&mut Keys>) {
    // A container for all the files that have been read
    // AKA the big blob of data
    let mut container_vec: Vec<FileData> = Vec::with_capacity(15);

    // Walk the directory and find all the files
    for entry in WalkDir::new(folder_path) {
        let entry = entry.unwrap();
        let entry_path = entry.path();

        if Path::new(entry_path).is_dir() {
            continue;
        }

        let file_handle = File::open(entry_path).expect("Failed to open the file.");

        // Compress + encrypt
        let mmap = unsafe { Mmap::map(&file_handle).expect("failed to map the file") };
        let file_data = &mmap[..];
        let file_size: usize = mmap.len();

        // Compress the file data
        let mut manipulated_data = compress_prepend_size(file_data);

        // Only encrypt the file if the keys are supplied
        match opt_keys {
            Some(ref keys) => {
                // Encrypt the file

                let key = Key::from_slice(keys.keypair.secret.as_bytes());
                let nonce = Nonce::from_slice(&keys.nonce);

                let cipher = ChaCha20Poly1305::new(key);

                // Encrypt the compressed data and overwrite the variable
                cipher
                    .encrypt_in_place(nonce, b"", &mut manipulated_data)
                    .unwrap();

                // Construct a new FileData struct
                let file: FileData = FileData::new(
                    entry_path.strip_prefix(folder_path).unwrap(),
                    file_size,
                    manipulated_data,
                );

                container_vec.push(file);
            }

            None => {
                // Construct a new FileData struct
                let file: FileData = FileData::new(
                    entry_path.strip_prefix(folder_path).unwrap(),
                    file_size,
                    manipulated_data,
                );
                container_vec.push(file);
            }
        }
    }

    // Now that all the files along with their metadata have been
    // read and stored in the container, encode it.
    let container: Container = Container::new(container_vec, vec![0]);
    let encoded_container =
        bincode::serialize(&container).expect("Failed to serialize the metadata");

    // Sign the data only if the keys are supplied.
    if let Some(keys) = opt_keys {
        keys.sign(&encoded_container);
    } else {
    }

    // write it to disk.
    let mut combined_file =
        File::create(format!("{file_path}.sf")).expect("Could not open/create the combined file.");

    combined_file
        .write_all(&encoded_container)
        .expect("Failed to write the combined file");
}

pub fn read_combined_file(file_path: String, keys: Option<&Keys>) -> Vec<FileData> {
    // Read the encoded data from the disk
    let mut container_fp = File::open(file_path).expect("Failed to open the combined file");
    let mut container_data = Vec::new();

    container_fp
        .read_to_end(&mut container_data)
        .expect("Failed to read the combined file");

    // Verify the data only if the keys are supplied.
    if let Some(keys) = keys {
        keys.verify(&container_data, &keys.signature);
        println!("I'm actually checking the signature...{:?}", keys.signature);
    }

    let decoded: Container =
        bincode::deserialize(&container_data[..]).expect("Failed to decode the combined file");

    let container_vec: Vec<FileData> = decoded.files;

    container_vec
}

pub async fn recreate_files(combined_data: Vec<FileData>, keys: Option<&Keys>) {
    let mut task_list = Vec::new();

    for mut file_data in combined_data {
        let filepath = file_data.path;

        std::fs::create_dir_all(filepath.parent().unwrap())
            .expect("Failed to create all the required directories/subdirectories");

        let mut file_write = tokio::fs::File::create(filepath)
            .await
            .expect("Failed to create the files while recreation");

        match keys {
            Some(keys) => {
                // Decrypt the file

                let key = Key::from_slice(keys.keypair.secret.as_bytes());
                let nonce = Nonce::from_slice(&keys.nonce);

                let cipher = ChaCha20Poly1305::new(key);

                // Encrypt the compressed data and overwrite the variable
                cipher
                    .encrypt_in_place(nonce, b"", &mut file_data.data)
                    .unwrap();

                // Decompress the data
                let decompressed_data = decompress_size_prepended(&file_data.data)
                    .expect("Failed to decompress the data.");

                let write_task = task::spawn(async move {
                    file_write
                        .write_all(&decompressed_data)
                        .await
                        .expect("Failed to write to new temp file.");

                    file_write.sync_all().await.expect("Failed to sync file");
                });

                task_list.push(write_task);
            }

            None => {
                // Decompress the data
                let decompressed_data = decompress_size_prepended(&file_data.data)
                    .expect("Failed to decompress the data.");

                let write_task = task::spawn(async move {
                    file_write
                        .write_all(&decompressed_data)
                        .await
                        .expect("Failed to write to new temp file.");

                    file_write.sync_all().await.expect("Failed to sync file");
                });

                task_list.push(write_task);
            }
        }
    }

    for val in task_list.into_iter() {
        val.await.err();
    }
}

pub fn shred_file(filepath: &str) {
    // Shred the file provided as an argument
    let mut file = File::create(filepath).expect("Failed to open the file.");
    let file_len = file.metadata().unwrap().len().try_into().unwrap();

    file.write_all(&vec![0u8; file_len])
        .expect("Failed to write to the file.");
}
