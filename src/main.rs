#![feature(seek_stream_len)]
mod encryption;

use serde::{Deserialize, Serialize};
use std::{
    env,
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use tokio::{io::AsyncWriteExt, task};
use walkdir::WalkDir;

fn shred_file(filepath: &str) {
    // Shred the file provided as an argument
    let mut file = File::create(filepath).expect("Failed to open the file.");
    let file_len = file.metadata().unwrap().len().try_into().unwrap();

    file.write_all(&vec![0u8; file_len])
        .expect("Failed to write to the file.");
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct FileData {
    metadata: (PathBuf, usize),
    data: Vec<u8>,
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
struct Container(Vec<FileData>);

fn create_combined_file(folder_path: &String) {
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

        // Construct a new FileData struct
        let file: FileData = FileData::new(
            entry_path.strip_prefix(folder_path).unwrap().to_path_buf(),
            file_size,
            file_data,
        );
        container_vec.push(file);
    }

    // Now that all the files along with their metadata have been
    // read and stored in the container, encode it.
    let container: Container = Container(container_vec);
    let encoded_metadata = bincode::serialize(&container).unwrap();

    // write it to disk.
    let mut combined_file = File::create("/tmp/testing").unwrap();
    combined_file.write_all(&encoded_metadata).unwrap();
}

fn read_combined_file() -> Vec<FileData> {
    // Read the encoded data from the disk
    let mut container_fp = File::open("/tmp/testing").unwrap();
    let mut container_data = Vec::new();
    container_fp.read_to_end(&mut container_data).unwrap();

    let decoded: Container = bincode::deserialize(&container_data[..]).unwrap();
    let container_vec: Vec<FileData> = decoded.0;
    return container_vec;
}

async fn recreate_files(combined_data: Vec<FileData>) {
    let mut task_list = Vec::new();
    for i in combined_data {
        let filepath = i.metadata.0;

        std::fs::create_dir_all(filepath.parent().unwrap()).unwrap();

        let mut file_write = tokio::fs::File::create(filepath).await.unwrap();

        let write_task = task::spawn(async move {
            file_write
                .write_all(&i.data)
                .await
                .expect("Failed to write to new temp file.")
        });
        task_list.push(write_task);
    }

    for val in task_list.into_iter() {
        val.await.err();
    }
}

#[tokio::main]
async fn main() {
    shred_file("/tmp/testing");
    let args: Vec<String> = env::args().collect();

    create_combined_file(&args[1]);

    let combined_data = read_combined_file();
    recreate_files(combined_data).await;
}
