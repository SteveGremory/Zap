use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Key, XChaCha20Poly1305, XNonce,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{self, Read, Write},
    path,
};
use walkdir::WalkDir;

#[derive(Clone, Serialize, Deserialize)]
struct Keys {
    key: Key,
    nonce: XNonce,
}

impl Keys {
    fn new() -> Self {
        let key = XChaCha20Poly1305::generate_key(&mut OsRng);
        Keys {
            key,
            nonce: XChaCha20Poly1305::generate_nonce(&mut OsRng),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CryptMode {
    Encrypt,
    Decrypt,
}

fn copy_crypt<R: Read + ?Sized, W: Write + ?Sized>(
    reader: &mut R,
    writer: &mut W,
    keys: Keys,
    mode: CryptMode,
) -> io::Result<usize> {
    const BUFFER_SIZE: usize = 4096;

    let mut vec_buffer: Vec<u8> = vec![0; BUFFER_SIZE];
    let cipher_instance = XChaCha20Poly1305::new(&keys.key);

    let mut final_len = 0;
    let mut encrypted_buffer: Vec<u8>;

    loop {
        let len: usize = reader.read(&mut vec_buffer).expect("Failed to read buffer");

        if len == 0 {
            break;
        }

        // Encrypt or decrypt the buffer
        if mode == CryptMode::Encrypt {
            encrypted_buffer = cipher_instance
                .encrypt(&keys.nonce, &vec_buffer[..len])
                .unwrap();
        } else {
            encrypted_buffer = cipher_instance
                .decrypt(&keys.nonce, &vec_buffer[..len])
                .unwrap();
        }

        final_len += len;
        writer.write(&encrypted_buffer);

        vec_buffer.clear();
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
    let mut rdr = lz4_flex::frame::FrameDecoder::new(input_file);
    let mut wtr = output_file;

    if let Some(keys) = keys {
        copy_crypt(&mut rdr, &mut wtr, keys, CryptMode::Decrypt).unwrap();
    } else {
        io::copy(&mut rdr, &mut wtr).expect("I/O operation failed");
    }
}

pub async fn directorize(
    input_folder_path: &str,
    output_folder_path: &str,
    is_decompressing: bool,
) {
    let mut task_list = Vec::with_capacity(800);

    if is_decompressing {
        // TODO: Fix encryption
        // write the keys to disk
        /*
            let mut keyfile = fs::File::open("keyfile.zk").expect("Could not open keyfile");
            let mut data: Vec<u8> = Vec::new();
            keyfile
                .read_to_end(data.as_mut())
                .expect("Failed to read keyfile");
            let keys: Keys = bincode::deserialize(&data).expect("Failed to serialize");
        */

        for entry in WalkDir::new(input_folder_path) {
            let entry = entry.unwrap();
            let entry_path = entry.into_path();

            if path::Path::new(&entry_path).is_dir() {
                continue;
            }

            if entry_path == path::Path::new("keyfile.zk") {
                continue;
            }

            if entry_path.extension().unwrap_or_default() == "lz4" {
                let parent_path = entry_path.strip_prefix(input_folder_path).unwrap();

                let output_path =
                    path::Path::new(output_folder_path).join(parent_path.with_extension(""));

                let current_dir = output_path.parent().unwrap();

                std::fs::create_dir_all(current_dir)
                    .expect("Failed to create all the required directories/subdirectories");

                // Shadow the prev. keys variable
                // let keys = keys.clone();

                let decompress_task = tokio::spawn(async {
                    let input_file = fs::File::open(entry_path).unwrap();
                    let output_file =
                        fs::File::create(output_path).expect("Failed to create file.");
                    decompress(input_file, output_file, None);
                });

                task_list.push(decompress_task);
            }
        }
    } else {
        /*
                let keys = Keys::new();
                // write the keys to disk
                let mut keyfile = fs::File::create("keyfile.zk").expect("Could not open keyfile");
                let serialized_keys = bincode::serialize(&keys).expect("Failed to serialize");
                keyfile
                    .write_all(&serialized_keys)
                    .expect("Failed to write keys to disk");
        */

        for entry in WalkDir::new(input_folder_path) {
            let entry = entry.unwrap();
            let entry_path = entry.into_path();

            if path::Path::new(&entry_path).is_dir() {
                continue;
            }

            if entry_path == path::Path::new("keyfile.zk") {
                continue;
            }

            let parent_path = entry_path.strip_prefix(input_folder_path).unwrap();
            let output_path =
                path::Path::new(output_folder_path).join(parent_path.with_extension(format!(
                "{}.lz4",
                parent_path
                    .extension()
                    .unwrap_or_default()
                    .to_str()
                    .unwrap_or_default()
            )));

            let current_dir = output_path.parent().unwrap();

            std::fs::create_dir_all(current_dir)
                .expect("Failed to create all the required directories/subdirectories");

            // Shadow the prev. keys variable
            //let keys = keys.clone();

            let compress_task = tokio::spawn(async {
                let input_file = fs::File::open(entry_path).unwrap();
                let output_file = fs::File::create(output_path).expect("Failed to create file.");
                compress(input_file, output_file, None);
            });

            task_list.push(compress_task);
        }
    }

    for val in task_list.into_iter() {
        val.await.err();
    }
}
