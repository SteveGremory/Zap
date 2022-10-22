mod encryption;
use argparse::{ArgumentParser, Store};

use lz4::block::{compress, decompress};
use serde::{Deserialize, Serialize};
use std::{
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

fn create_combined_file(folder_path: &String, file_path: &String) {
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
        let compressed_data = compress(&file_data, None, true).unwrap();

        // Construct a new FileData struct
        let file: FileData = FileData::new(
            entry_path.strip_prefix(folder_path).unwrap().to_path_buf(),
            file_size,
            compressed_data,
        );
        container_vec.push(file);
    }

    // Now that all the files along with their metadata have been
    // read and stored in the container, encode it.
    let container: Container = Container(container_vec);
    let encoded_metadata = bincode::serialize(&container).unwrap();

    // write it to disk.
    let mut combined_file = File::create(file_path).unwrap();
    combined_file.write_all(&encoded_metadata).unwrap();
}

fn read_combined_file(file_path: String) -> Vec<FileData> {
    // Read the encoded data from the disk
    let mut container_fp = File::open(file_path).unwrap();
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

        // Decompress the data
        let decompressed_data = decompress(&i.data, None).unwrap();

        let write_task = task::spawn(async move {
            file_write
                .write_all(&decompressed_data)
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
    let mut folder_path = String::new();
    let mut output_path = String::new();
    let mut file_path = String::new();

    {
        let mut ap = ArgumentParser::new();
        ap.set_description("SecureFolder V0.1: Encrypt and package a given folder into one file.");

        ap.refer(&mut folder_path).add_option(
            &["--folderpath"],
            Store,
            "Path to the folder to be encrypted.",
        );

        ap.refer(&mut file_path).add_option(
            &["--filepath"],
            Store,
            "Path to the combined file to be accessed; the contents will be placed in the current directory.",
        );
        ap.refer(&mut output_path)
            .add_option(
                &["-o", "--output"],
                Store,
                "Path to the output file; Beware if a file exists with the same name, that the file will be shredded.",
            );

        ap.parse_args_or_exit();
    }

    // If an output file isn't found, then tell the user to create one
    // as rust is facing issues creating files on macOS.
    if !output_path.is_empty() {
        if !Path::new(&output_path).exists() {
            panic!(
                "File {} was not found. Please create it before proceeding.",
                output_path
            );
        } else {
            // Shred the previous file with that name
            shred_file(&output_path);
        }
    }

    // If a combined file is to be created, do so
    // if not, then recreate the file strucutre from the combined file.
    if file_path.is_empty() {
        // Create a combined file from the folder
        create_combined_file(&folder_path, &output_path);
    } else {
        // Recreate the file structure that was combined.
        let combined_data = read_combined_file(file_path);
        recreate_files(combined_data).await;
    }
}
