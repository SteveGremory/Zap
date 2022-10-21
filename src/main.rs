#![feature(seek_stream_len)]
mod encryption;

use std::io::{BufRead, BufReader, Read};
use std::vec;
use std::{env, path::Path};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use walkdir::WalkDir;

async fn encrypt_folder(folderpath: &str) {
    // Open the folder
    // Check out all the files

    // Combine it all into one file
    // Write it all sequentially as one big blob of data

    /* Write Structure:
        filecount: x;

        filesize1,filename1
        filesize2,filename2

    */

    /*
        {file data1}
        {file data2}
    */

    let mut current_file_data = Vec::new();
    current_file_data.reserve(5 * 10_usize.pow(6));

    let mut combined_file_data = Vec::new();
    combined_file_data.reserve(500 * 10_usize.pow(6));

    let mut combined_file_metadata = Vec::new();

    let mut combined_file = File::create("/tmp/testing")
        .await
        .expect("Could not open temp file.");

    for entry in WalkDir::new(folderpath) {
        let entry = entry.unwrap();
        let entry_path = entry.path().display().to_string();

        if Path::new(entry_path.as_str()).is_dir() {
            continue;
        }

        println!("Path: {}", entry_path);
        let mut current_file_handle = File::open(&entry_path)
            .await
            .expect(format!("Failed to open: {}", entry_path).as_str());

        let current_file_size: usize = current_file_handle
            .read_to_end(&mut current_file_data)
            .await
            .expect("Failed to read the specified file.");

        combined_file_data.append(&mut current_file_data);
        current_file_data.clear();

        combined_file_metadata.push(format!(
            "{},{}",
            current_file_size,
            entry
                .path()
                .strip_prefix(folderpath)
                .unwrap()
                .to_str()
                .unwrap()
        ))
    }

    // Encode the metadata
    let encoded_metadata =
        bincode::serialize(&combined_file_metadata).expect("Could not encode vector");
    // Write the encoded metadata
    combined_file
        .write_all(format!("{:?}\n", encoded_metadata).as_bytes())
        .await
        .expect("Failed to write to the combined file.");

    combined_file
        .write_all(&combined_file_data)
        .await
        .expect("Failed to write to the combined file.");

    // encrypt the big file
    // Hash the big file
}

async fn decrypt_folder() {
    // Read the whole big blob of data
    let file = File::open("/tmp/testing")
        .await
        .expect("Failed to open /tmp/testing.");

    let mut buffer = BufReader::new(file.into_std().await);

    // Read the first line of the file containing all the metadata
    let mut files_metadata = String::new();
    buffer
        .read_line(&mut files_metadata)
        .expect("Failed to read /tmp/testing");
    // Prase the metadata as a Vec<u8> from a string
    let parsed_metadata: Vec<u8> =
        // Remove the newline
        ron::from_str(&files_metadata[..(files_metadata.len() - 1)]).unwrap();
    // Deserialize the metadata
    let decoded_combined_metadata: Vec<String> =
        bincode::deserialize(&parsed_metadata).expect("Failed to decode the combined metadata.");

    let mut combined_data = Vec::new();
    buffer.read_to_end(&mut combined_data).unwrap();

    let mut prev_size = 0;
    for i in decoded_combined_metadata {
        // Split the string into [filesize, filename]
        let split_string: Vec<&str> = i.split(",").collect();
        // Extract the size of the current file from the vector
        let current_size = split_string[0].parse::<usize>().unwrap();
        // Extract the data from the huge blob by using indexes
        let current_data = &combined_data[prev_size..(current_size + prev_size)];

        println!("{}", split_string[1]);
        let prefix = std::path::Path::new(split_string[1]).parent().unwrap();

        std::fs::create_dir_all(prefix).unwrap();
        let mut file_write = File::create(split_string[1]).await.unwrap();

        file_write
            .write_all(&current_data)
            .await
            .expect("Failed to write to new temp file.");

        prev_size = current_size;
    }
}

async fn shred_file(filepath: &str) {
    // Shred the file provided as an argument
    let mut file = File::create(filepath)
        .await
        .expect("Failed to open the file.");

    let file_len = file.metadata().await.unwrap().len().try_into().unwrap();

    file.write_all(&vec![0u8; file_len])
        .await
        .expect("Failed to write to the file.");
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    shred_file("/tmp/testing").await;
    encrypt_folder(&args[1]).await;
    decrypt_folder().await;

    // println!("Args: \n{}", args[1]);
    // shred_file(&args[1]);
}
