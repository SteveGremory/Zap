use crate::encryption::*;
use lz4::block::{compress, decompress};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use tokio::{io::AsyncWriteExt, task};
use walkdir::WalkDir;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct FileData {
    pub metadata: (PathBuf, usize),
    pub data: Vec<u8>,
}

impl FileData {
    fn new(file_path: PathBuf, len: usize, data: Vec<u8>) -> Self {
        return FileData {
            metadata: (file_path, len),
            data: data,
        };
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Container(Vec<FileData>);

pub fn create_combined_file(folder_path: &String, file_path: &String, keypair: Option<&Keypair>) {
    // A container for all the files that have been read
    // AKA the big blob of data
    let mut container_vec: Vec<FileData> = Vec::new();

    // Walk the directory and find all the files
    for entry in WalkDir::new(folder_path) {
        let entry = entry.unwrap();
        let entry_path = entry.path();

        if Path::new(entry_path).is_dir() {
            continue;
        }

        let mut file_handle = File::open(entry_path).expect("Failed to open the file.");

        let mut file_data: Vec<u8> = Vec::new();
        let file_size: usize = file_handle
            .read_to_end(&mut file_data)
            .expect("Failed to read the specified file.");

        // Compress the file data
        let compressed_data = compress(
            &file_data,
            Some(lz4::block::CompressionMode::HIGHCOMPRESSION(8)),
            true,
        )
        .expect("Failed to compress the data");
        match keypair {
            Some(keypair) => {
                // Encrypt the file
                let encrypted_data = encrypt(compressed_data, &keypair.key, &keypair.nonce)
                    .expect("Failed to encrypt the data.");

                // Construct a new FileData struct
                let file: FileData = FileData::new(
                    entry_path.strip_prefix(folder_path).unwrap().to_path_buf(),
                    file_size,
                    encrypted_data,
                );
                container_vec.push(file);
            }

            None => {
                // Construct a new FileData struct
                let file: FileData = FileData::new(
                    entry_path.strip_prefix(folder_path).unwrap().to_path_buf(),
                    file_size,
                    compressed_data,
                );
                container_vec.push(file);
            }
        }
    }

    // Now that all the files along with their metadata have been
    // read and stored in the container, encode it.
    let container: Container = Container(container_vec);
    let encoded_metadata =
        bincode::serialize(&container).expect("Failed to serialize the metadata");

    // write it to disk.
    let mut combined_file =
        File::create(file_path).expect("Could not open/create the combined file.");
    combined_file
        .write_all(&encoded_metadata)
        .expect("Failed to write the combined file");
}

pub fn read_combined_file(file_path: String) -> Vec<FileData> {
    // Read the encoded data from the disk
    let mut container_fp = File::open(file_path).expect("Failed to open the combined file");
    let mut container_data = Vec::new();
    container_fp
        .read_to_end(&mut container_data)
        .expect("Failed to read the combined file");

    let decoded: Container =
        bincode::deserialize(&container_data[..]).expect("Failed to decode the combined file");
    let container_vec: Vec<FileData> = decoded.0;
    return container_vec;
}

pub async fn recreate_files(combined_data: Vec<FileData>, keypair: Option<&Keypair>) {
    let mut task_list = Vec::new();
    for i in combined_data {
        let filepath = i.metadata.0;

        std::fs::create_dir_all(filepath.parent().unwrap())
            .expect("Failed to create all the required directories/subdirectories");

        let mut file_write = tokio::fs::File::create(filepath)
            .await
            .expect("Failed to create the files while recreation");

        match keypair {
            Some(keypair) => {
                // Decrypt the file
                let decrypted_data = decrypt(i.data, &keypair.key, &keypair.nonce)
                    .expect("Failed to decrypt the data");

                // Decompress the data
                let decompressed_data =
                    decompress(&decrypted_data, None).expect("Failed to decompress the data");

                let write_task = task::spawn(async move {
                    file_write
                        .write_all(&decompressed_data)
                        .await
                        .expect("Failed to write to new temp file.")
                });
                task_list.push(write_task);
            }

            None => {
                // Decompress the data
                let decompressed_data =
                    decompress(&i.data, None).expect("Failed to decompress the data.");

                let write_task = task::spawn(async move {
                    file_write
                        .write_all(&decompressed_data)
                        .await
                        .expect("Failed to write to new temp file.")
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
