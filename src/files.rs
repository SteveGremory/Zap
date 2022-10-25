pub mod reading;
pub mod streaming;

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Debug)]
pub struct FileData {
    pub path: PathBuf,
    pub len: usize,
    pub data: Vec<u8>,
}

impl FileData {
    fn new<P: AsRef<Path>>(file_path: P, len: usize, data: Vec<u8>) -> Self {
        FileData {
            path: file_path.as_ref().to_owned(),
            len,
            data,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Container {
    files: Vec<FileData>,
    signature: Vec<u8>,
}

impl Container {
    fn new(files: Vec<FileData>, signature: Vec<u8>) -> Self {
        Container { files, signature }
    }
}
