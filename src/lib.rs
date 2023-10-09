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
    path::{self, Path, PathBuf}, sync::Arc, backtrace,
};

use compression::{lz4::Lz4Algorithm, CompressionAlgorithm, DecompressionAlgorithm};
use crossbeam::sync::WaitGroup;
use encryption::{passthrough::{EncryptorPassthrough, DecryptorPassthrough}, xchachapoly::XChaChaPolyAlgorithm, EncryptionAlgorithm};
use error::{CompressionError, DecompressionError};
use log::{info, error};
use password::EncryptionSecret;
use pipeline::{CompressionPipeline, DecompressionPipeline};
use rayon::ThreadPoolBuilder;
use signing::passthrough::{SignerPassthrough, VerifierPassthrough};
use walkdir::WalkDir;
use crate::encryption::DecryptionAlgorithm;

pub fn compress_directory
(
    input_folder_path: &str,
    output_folder_path: &str,
    secret: Option<EncryptionSecret>,
) -> Result<(), CompressionError> 
{
    let thread_pool = ThreadPoolBuilder::new()
        .num_threads(16)
        .build()?;

    let wg = WaitGroup::new();
    
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

        let parent_path = match entry_path.strip_prefix(input_folder_path) {
            Ok(p) => p,
            Err(e) => panic!("Error: {:?}", e), // TODO: Graceful cleanup
        };
        
        let output_path =
            path::Path::new(output_folder_path).join(
                rewrite_ext(parent_path));

        info!("Compressing: {:?} -> {:?}", entry_path.display(), output_path.display());

        let current_dir = output_path.parent().unwrap();

        std::fs::create_dir_all(current_dir)
            .expect("Failed to create all the required directories/subdirectories");

        let secret_ref = secret_ref.clone();
        let wg_ref = wg.clone();

        thread_pool.spawn(
        move || {

            let result = std::panic::catch_unwind(
                ||  {
                    let mut source = match fs::File::open(&entry_path) {
                        Ok(f) => f,
                        Err(e) => panic!("Error: {:?}", e), // TODO: Graceful cleanup
                    };
        
                    let destination = match fs::File::create(&output_path) {
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

                                let comp = match Lz4Algorithm::new().compressor(enc) {
                                    Ok(c) => c,
                                    Err(e) => panic!("Failed to build compress while compressing '{:?}': {:?}", output_path.display(), e), // TODO: Graceful cleanup
                                };

                                let sign = SignerPassthrough::from(comp);

                                let pipeline = pipeline::TaskPipeline::from_writer(sign);

                                match pipeline.compress(&mut source) {
                                    Ok(_) => info!("Finished compressing '{:?}' successfully", entry_path.display()),
                                    Err(e) => {
                                        let bt = backtrace::Backtrace::capture();
                                        error!("Error while compressing '{}': {:?}", entry_path.display(), e);
                                        log::trace!("Error while compressing '{}': {:?}", entry_path.display(), bt);
                                        panic!();
                                    },
                                };
                            },
                            EncryptionSecret::Key(_p) => unimplemented!("Keyfile encryption not implemented yet"),
                        },
                        None => {
                            let enc = EncryptorPassthrough::from(destination);
                            let comp = match Lz4Algorithm::new().compressor(enc) {
                                Ok(c) => c,
                                Err(e) => panic!("Failed to build compress while compressing '{:?}': {:?}", output_path.display(), e), // TODO: Graceful cleanup
                            };
                            let sign = SignerPassthrough::from(comp);
        
                            let pipeline = pipeline::TaskPipeline::from_writer(sign);
        
                            match pipeline.compress(&mut source) {
                                Ok(_) => info!("Finished compressing '{:?}' successfully", entry_path.display()),
                                Err(e) => {
                                    let bt = backtrace::Backtrace::capture();
                                    error!("Error while compressing '{}': {:?}", entry_path.display(), e);
                                    log::trace!("Error while compressing '{}': {:?}", entry_path.display(), bt);
                                    panic!();
                                },
                            };
                        }
                    };
        
                    drop(wg_ref);
                }
            );

            match result {
                Ok(_) => {},
                Err(e) => {
                    log::trace!("Thread panicked while handling file: {:?}\nMessage: {:?}", entry_path.display(), e);
                }
            }
        });
    }

    wg.wait();

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
        .num_threads(1)
        .build()?;

    let wg = WaitGroup::new();

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
                
            info!("Decompressing: {:?} -> {:?}", entry_path.display(), output_path.display());

            let current_dir = output_path.parent().unwrap();

            std::fs::create_dir_all(current_dir)
                .expect("Failed to create all the required directories/subdirectories");

            let secret_ref = secret_ref.clone();
            let wg_ref = wg.clone();

            thread_pool.spawn(

            move || {
                let result = std::panic::catch_unwind(
                    || {
                        let source = match fs::File::open(&entry_path) {
                            Ok(f) => f,
                            Err(e) => panic!("Error: {:?}", e), // TODO: Graceful cleanup
                        };
        
                        let mut destination = match fs::File::create(&output_path) {
                            Ok(f) => f,
                            Err(e) => panic!("Error: {:?}", e), // TODO: Graceful cleanup
                        };
        
                        match secret_ref.as_ref() {
        
                            Some(p) => match p {
                                EncryptionSecret::Password(p) => {
                                    let enc = match XChaChaPolyAlgorithm::new()
                                        .with_key(p.clone())
                                        .decryptor(source){
                                            Ok(e) => e,
                                            Err(e) => panic!("Error: {:?}", e), // TODO: Graceful cleanup
                                        };

                                    let comp = match Lz4Algorithm::new().decompressor(enc) {
                                        Ok(c) => c,
                                        Err(e) => panic!("Error: {:?}", e), // TODO: Graceful cleanup
                                    };

                                    let sign = VerifierPassthrough::from(comp);

                                    let pipeline = pipeline::TaskPipeline::from_reader(sign);

                                    match pipeline.decompress(&mut destination) {
                                        Ok(_) => info!("Finished decompressing '{:?}' successfully", entry_path.display()),
                                        Err(e) => {
                                            let bt = backtrace::Backtrace::capture();
                                            error!("Error while decompressing '{}': {:?}", entry_path.display(), e);
                                            log::trace!("Error while decompressing '{}': {:?}", entry_path.display(), bt);
                                            panic!();
                                        },
                                    };
                                },
                                EncryptionSecret::Key(_p) => unimplemented!("Keyfile encryption not implemented yet"),
                            },
                            None => {
                                info!("Building decompressor: {:?} -> {:?}", entry_path.display(), output_path.display());
        
                                let enc = DecryptorPassthrough::from(source);
                                let comp = match Lz4Algorithm::new().decompressor(enc) {
                                    Ok(c) => c,
                                    Err(e) => panic!("Error: {:?}", e), // TODO: Graceful cleanup
                                };
                                let sign = VerifierPassthrough::from(comp);
        
                                let pipeline = pipeline::TaskPipeline::from_reader(sign);
        
                                info!("Starting decompression: {:?} -> {:?}", entry_path.display(), output_path.display());
        
                                match pipeline.decompress(&mut destination) {
                                    Ok(_) => info!("Finished decompressing '{:?}' successfully", entry_path.display()),
                                    Err(e) => {
                                        let bt = backtrace::Backtrace::capture();
                                        error!("Error while decompressing '{}': {:?}", entry_path.display(), e);
                                        log::trace!("Error while decompressing '{}': {:?}", entry_path.display(), bt);
                                        panic!();
                                    },
                                };
                            }
                        };
        
                        drop(wg_ref)
                    });
                
                match result {
                    Ok(_) => {},
                    Err(e) => {
                        log::trace!("Thread panicked while handling file: {:?}\nMessage: {:?}", entry_path.display(), e);
                    }
                }
            });
        }
    }

    wg.wait();

    Ok(())
}

fn rewrite_ext(path: &Path) -> PathBuf {
    match path.extension() {
        Some(ext) => path.with_extension(format!("{}.lz4", ext.to_str().unwrap())),
        None => path.with_extension("lz4"),
    }
}