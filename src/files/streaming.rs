/*
use chacha20poly1305::{
    aead::{AeadCore, KeyInit, OsRng},
    AeadInPlace, ChaCha20Poly1305, Nonce,
};

use std::{fs, io, path};
use tokio::*;
use walkdir::WalkDir;

#[derive(Clone)]
struct Keys {
    nonce: Nonce,
    cipher: ChaCha20Poly1305,
}

impl Keys {
    fn new() -> Self {
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        Keys {
            cipher: ChaCha20Poly1305::new(&key),
            nonce: ChaCha20Poly1305::generate_nonce(&mut OsRng),
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CryptMode {
    Encrypt,
    Decrypt,
}

fn copy_crypt<R: io::Read + ?Sized, W: io::Write + ?Sized>(
    reader: &mut R,
    writer: &mut W,
    keys: Keys,
    mode: CryptMode,
) -> io::Result<usize> {
    const BUFFER_SIZE: usize = 4096;
    let mut vec_buffer: Vec<u8> = vec![0; BUFFER_SIZE];

    let mut final_len = 0;

    loop {
        let len: usize = reader.read(&mut vec_buffer).expect("Failed to read buffer");

        if len == 0 {
            break;
        }

        // Encrypt or decrypt the buffer
        if mode == CryptMode::Encrypt {
            keys.cipher
                .encrypt_in_place(&keys.nonce, b"", &mut vec_buffer)
                .unwrap();
        } else {
            keys.cipher
                .decrypt_in_place(&keys.nonce, b"", &mut vec_buffer)
                .unwrap();
        }

        final_len += len;
        writer.write_all(&vec_buffer[..len])?;
    }

    Ok(final_len)
}

fn compress(input_file: fs::File, output_file: fs::File, keys: Option<Keys>) {
    let mut wtr = lz4_flex::frame::FrameEncoder::new(output_file);
    let mut rdr = input_file;

    if let Some(keys) = keys {
        copy_crypt(&mut rdr, &mut wtr, keys, CryptMode::Encrypt).unwrap();
    } else {
        io::copy(&mut rdr, &mut wtr).expect("I/O operation failed");
    }

    wtr.finish().unwrap();
}

fn decompress(input_file: fs::File, output_file: fs::File, keys: Option<Keys>) {
    let mut wtr = lz4_flex::frame::FrameDecoder::new(output_file);
    let mut rdr = input_file;

    if let Some(keys) = keys {
        copy_crypt(&mut wtr, &mut rdr, keys, CryptMode::Decrypt).unwrap();
    } else {
        io::copy(&mut wtr, &mut rdr).expect("I/O operation failed");
    }
}

#[tokio::main]
async fn main() {
    let folder_path = "/Users/steve/Downloads/";
    let mut task_list = Vec::with_capacity(800);
    //let is_compressing = true;

    let keys = Keys::new();

    for entry in WalkDir::new(folder_path) {
        let entry = entry.unwrap();
        let entry_path = entry.path();

        if path::Path::new(entry_path).is_dir() {
            continue;
        }

        let input_file = fs::File::open(entry_path).unwrap();

        let parent_path = entry_path.strip_prefix(folder_path).unwrap();
        let output_path = parent_path.with_extension(format!(
            "{}.lz4",
            parent_path
                .extension()
                .unwrap_or_default()
                .to_str()
                .unwrap_or_default()
        ));

        let current_dir = output_path.parent().unwrap();

        std::fs::create_dir_all(current_dir)
            .expect("Failed to create all the required directories/subdirectories");

        let output_file = fs::File::create(output_path).expect("Failed to create file.");

        // Shadow the prev. keys variable
        let keys = keys.clone();
        let compress_task = task::spawn(async move {
            compress(input_file, output_file, Some(keys));
        });

        task_list.push(compress_task);
    }

    for val in task_list.into_iter() {
        val.await.err();
    }
}
*/
