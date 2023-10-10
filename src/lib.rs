pub mod compression;
pub mod encryption;
pub mod error;
pub mod internal;
pub mod pipeline;
pub mod prelude;
pub mod signing;

use std::{
    backtrace,
    path::{self, Path, PathBuf},
    sync::Arc,
};

use crate::pipeline::ProcessingPipeline;
use compression::CompressionType;
use crossbeam::sync::WaitGroup;
use encryption::{EncryptionSecret, EncryptionType};
use error::{CompressionError, DecompressionError};
use log::{debug, error};
use rayon::ThreadPoolBuilder;
use signing::SigningType;
use walkdir::WalkDir;

pub struct Processor {}

pub fn compress_directory(
    input_folder_path: &str,
    output_folder_path: &str,
    encryption: EncryptionType,
    encryption_secret: EncryptionSecret,
    compression: CompressionType,
    compression_level: flate2::Compression,
    signing: SigningType,
) -> Result<(), CompressionError> {
    let avail_thread: usize = std::thread::available_parallelism()?.into();

    debug!("Building thread pool with {} threads", avail_thread);

    let thread_pool = ThreadPoolBuilder::new().num_threads(avail_thread).build()?;

    let wg = WaitGroup::new();

    let encryption_ref = Arc::new(encryption);
    let compression_ref = Arc::new(compression);
    let compression_level_ref = Arc::new(compression_level);
    let signing_ref = Arc::new(signing);
    let encryption_secret_ref = Arc::new(encryption_secret);

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

        let output_path = path::Path::new(output_folder_path).join(rewrite_ext(parent_path));

        debug!(
            "Compressing: {:?} -> {:?}",
            entry_path.display(),
            output_path.display()
        );

        let current_dir = output_path.parent().unwrap();

        std::fs::create_dir_all(current_dir)
            .expect("Failed to create all the required directories/subdirectories");

        let encryption_secret_ref = encryption_secret_ref.clone();
        let encryption_ref = encryption_ref.clone();
        let compression_ref = compression_ref.clone();
        let compression_level_ref = compression_level_ref.clone();
        let signing_ref = signing_ref.clone();

        let wg_ref = wg.clone();

        thread_pool.spawn(move || {
            let result = std::panic::catch_unwind(|| {
                let pipeline = ProcessingPipeline::new()
                    .with_source(entry_path.clone())
                    .with_destination(output_path.clone())
                    .with_compression(compression_ref)
                    .with_compression_level(compression_level_ref)
                    .with_encryption(encryption_ref)
                    .with_encryption_secret(encryption_secret_ref)
                    .with_signing(signing_ref);

                match pipeline.compress_dir() {
                    Ok(_) => debug!(
                        "Finished compressing '{:?}' successfully",
                        entry_path.display()
                    ),
                    Err(e) => {
                        let bt = backtrace::Backtrace::capture();
                        error!(
                            "Error while compressing '{}': {:?}",
                            entry_path.display(),
                            e
                        );
                        log::trace!(
                            "Error while compressing '{}': {:?}",
                            entry_path.display(),
                            bt
                        );
                        panic!();
                    }
                };

                drop(wg_ref);
            });

            match result {
                Ok(_) => {}
                Err(e) => {
                    log::trace!(
                        "Thread panicked while handling file: {:?}\nMessage: {:?}",
                        entry_path.display(),
                        e
                    );
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
    encryption: EncryptionType,
    encryption_secret: EncryptionSecret,
    compression: CompressionType,
    signing: SigningType,
) -> Result<(), DecompressionError> {
    let avail_thread: usize = std::thread::available_parallelism()?.into();

    debug!("Building thread pool with {} threads", avail_thread);

    let thread_pool = ThreadPoolBuilder::new().num_threads(avail_thread).build()?;

    let wg = WaitGroup::new();

    let encryption_ref = Arc::new(encryption);
    let compression_ref = Arc::new(compression);
    let signing_ref = Arc::new(signing);
    let encryption_secret_ref = Arc::new(encryption_secret);

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

            debug!(
                "Decompressing: {:?} -> {:?}",
                entry_path.display(),
                output_path.display()
            );

            let current_dir = output_path.parent().unwrap();

            std::fs::create_dir_all(current_dir)
                .expect("Failed to create all the required directories/subdirectories");

            let encryption_secret_ref = encryption_secret_ref.clone();
            let encryption_ref = encryption_ref.clone();
            let compression_ref = compression_ref.clone();
            let signing_ref = signing_ref.clone();

            let wg_ref = wg.clone();

            thread_pool.spawn(move || {
                let result = std::panic::catch_unwind(|| {
                    let pipeline = ProcessingPipeline::new()
                        .with_source(entry_path.clone())
                        .with_destination(output_path.clone())
                        .with_compression(compression_ref)
                        .with_encryption(encryption_ref)
                        .with_encryption_secret(encryption_secret_ref)
                        .with_signing(signing_ref);

                    match pipeline.decompress_dir() {
                        Ok(_) => debug!(
                            "Finished decompressing '{:?}' successfully",
                            entry_path.display()
                        ),
                        Err(e) => {
                            let bt = backtrace::Backtrace::capture();
                            error!(
                                "Error while decompressing '{}': {:?}",
                                entry_path.display(),
                                e
                            );
                            log::trace!(
                                "Error while decompressing '{}': {:?}",
                                entry_path.display(),
                                bt
                            );
                            panic!();
                        }
                    };

                    drop(wg_ref)
                });

                match result {
                    Ok(_) => {}
                    Err(e) => {
                        log::trace!(
                            "Thread panicked while handling file: {:?}\nMessage: {:?}",
                            entry_path.display(),
                            e
                        );
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
