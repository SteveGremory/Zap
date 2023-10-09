pub mod compression;
pub mod encryption;
pub mod internal;
pub mod signing;
pub mod prelude;
pub mod error;
pub mod password;
pub mod pipeline;
mod util;

use std::{
    fs::{self},
    path, sync::Arc,
};

use compression::{compress, decompress, algorithms::lz4_decoder, lz4::Lz4Algorithm, CompressionAlgorithm, DecompressionAlgorithm};
use encryption::{passthrough::{EncryptorPassthrough, DecryptorPassthrough}, xchachapoly::XChaChaPolyAlgorithm, EncryptionAlgorithm};
use error::{CompressionError, DecompressionError};
use internal::bind_io_constructors;
use password::{convert_pw_to_key, EncryptionSecret};
use pipeline::{CompressionPipeline, DecompressionPipeline};
use rayon::ThreadPoolBuilder;
use signing::{signers::{signer_passthrough, verifier_passthrough}, passthrough::{SignerPassthrough, VerifierPassthrough}};
use walkdir::WalkDir;
use crate::compression::algorithms::lz4_encoder;

pub fn compress_directory
(
    input_folder_path: &str,
    output_folder_path: &str,
    secret: Option<EncryptionSecret>,
) -> Result<(), CompressionError> 
{
    let thread_pool = ThreadPoolBuilder::new()
        .num_threads(4)
        .build()?;
    
    let secret_ref = Arc::new(secret);

    for entry in WalkDir::new(input_folder_path) {
        let entry = entry?;
        let entry_path = entry.into_path();

        // Skip if it's a dir
        if entry_path.is_dir() {
            continue;
        }

        // Ignore the keyfile TODO
        if entry_path.as_os_str() == "keyfile.zk" {
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

        let secret_ref = secret_ref.clone();

        thread_pool.spawn(
        move || {
            let mut source = match fs::File::open(entry_path) {
                Ok(f) => f,
                Err(e) => panic!("Error: {:?}", e), // TODO: Graceful cleanup
            };

            let destination = match fs::File::create(output_path) {
                Ok(f) => f,
                Err(e) => panic!("Error: {:?}", e), // TODO: Graceful cleanup
            };

            match secret_ref.as_ref() {
                Some(p) => match p {
                    EncryptionSecret::Password(p) => {
                        let enc = XChaChaPolyAlgorithm::new()
                            .with_key(p.clone())
                            .encryptor(destination)
                            .unwrap();
                    },
                    EncryptionSecret::Key(p) => unimplemented!("Keyfile encryption not implemented yet"),
                },
                None => {
                    let enc = EncryptorPassthrough::from(destination);
                    let comp = match Lz4Algorithm::new().compressor(enc) {
                        Ok(c) => c,
                        Err(e) => panic!("Error: {:?}", e), // TODO: Graceful cleanup
                    };
                    let sign = SignerPassthrough::from(comp);

                    let pipeline = pipeline::TaskPipeline::from_writer(sign);

                    match pipeline.compress(&mut source) {
                        Ok(_) => println!("Success!"),
                        Err(e) => panic!("Error: {:?}", e),
                    };
                }
            };
        });
    }

    Ok(())
}

// todo: This function will alter the filename of binary files eg:
// a binary called 'someBinary' will end up as 'someBinary.'
pub fn decompress_directory(
    input_folder_path: &str,
    output_folder_path: &str,
    secret: Option<EncryptionSecret>
) -> Result<(), DecompressionError>
{
    let thread_pool = ThreadPoolBuilder::new()
        .num_threads(4)
        .build()?;

    let secret_ref = Arc::new(secret);
    
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

            let secret_ref = secret_ref.clone();

            thread_pool.spawn(

            move || {
                let mut source = match fs::File::open(entry_path) {
                    Ok(f) => f,
                    Err(e) => panic!("Error: {:?}", e), // TODO: Graceful cleanup
                };

                let destination = match fs::File::create(output_path) {
                    Ok(f) => f,
                    Err(e) => panic!("Error: {:?}", e), // TODO: Graceful cleanup
                };

                match secret_ref.as_ref() {
                    Some(p) => match p {
                        EncryptionSecret::Password(p) => {
                            let enc = XChaChaPolyAlgorithm::new()
                                .with_key(p.clone())
                                .encryptor(destination)
                                .unwrap();
                        },
                        EncryptionSecret::Key(p) => unimplemented!("Keyfile encryption not implemented yet"),
                    },
                    None => {
                        let enc = DecryptorPassthrough::from(destination);
                        let comp = match Lz4Algorithm::new().decompressor(enc) {
                            Ok(c) => c,
                            Err(e) => panic!("Error: {:?}", e), // TODO: Graceful cleanup
                        };
                        let sign = VerifierPassthrough::from(comp);

                        let pipeline = pipeline::TaskPipeline::from_reader(sign);

                        match pipeline.decompress(&mut source) {
                            Ok(_) => println!("Success!"),
                            Err(e) => panic!("Error: {:?}", e),
                        };
                    }
                };
            });
        }
    }
    Ok(())
}
