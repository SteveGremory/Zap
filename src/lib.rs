pub mod compression;
pub mod encryption;
pub mod internal;
pub mod signing;

use std::{
    fs::{self, File},
    io::{self, Read},
    path,
};

use compression::{Cleanup, compress, decompress, algorithms::lz4_decoder};
use encryption::{algorithm::{aes256, aes256_r}, convert_pw_to_key, Encryptor};
use crate::{compression::algorithms::Lz4Encoder, encryption::{encryption_passthrough, EncryptionPassthrough}};
use internal::{process_unit, build_writer};
use signing::signers::{signer_passthrough, SignerPassthrough, verifier_passthrough};
use walkdir::WalkDir;

use crate::compression::algorithms::lz4_encoder;

pub async fn compress_directory(
    input_folder_path: &str,
    output_folder_path: &str,
) -> io::Result<()> 
{
    let psk: Vec<u8> = convert_pw_to_key("password".to_owned(), 256).unwrap();
    let mut task_list = Vec::with_capacity(800);

    for entry in WalkDir::new(input_folder_path) {
        let entry = entry?;
        let entry_path = entry.into_path();

        // Skip if it's a dir
        if entry_path.is_dir() {
            continue;
        }

        // Ignore the keyfile
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

        let pass = psk.clone();
        std::fs::create_dir_all(current_dir)
            .expect("Failed to create all the required directories/subdirectories");
        // Rewrite to return errors
        let compress_task = tokio::spawn(async move {

            let writer = build_writer(
                //aes256(
                //    pass.clone(),
                //    pass
                //),
                encryption_passthrough,
                lz4_encoder, 
                signer_passthrough
            );

            /*let writer = build_writer(
                
                writer_algorithm, 
                signer_passthrough
            );*/

            dbg!(compress::<std::fs::File, SignerPassthrough<Lz4Encoder<EncryptionPassthrough<fs::File>>>, fs::File>(
                fs::File::open(entry_path).expect("Failed to open input file"),
                writer(fs::File::create(output_path))
            ));
        });

        task_list.push(compress_task);
    }

    for val in task_list.into_iter() {
        val.await.err();
    }

    Ok(())
}

pub async fn decompress_directory(
    input_folder_path: &str,
    output_folder_path: &str,
) -> io::Result<()>
{
    let psk: Vec<u8> = convert_pw_to_key("password".to_owned(), 256).unwrap();
    
    let mut task_list = Vec::with_capacity(800);
    
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


            let reader = build_writer(
                aes256_r(
                    psk.clone(),
                    psk.clone()
                ),        
                lz4_decoder, 
                verifier_passthrough,
            );

            let decompress_task = tokio::spawn(async move {
                dbg!(decompress(
                    reader(
                        fs::File::open(entry_path)
                    ),
                    fs::File::create(output_path).expect("Failed to create file.")
                ));
            });

            task_list.push(decompress_task);
        }
    }

    for val in task_list.into_iter() {
        val.await.err();
    }

    Ok(())
}
