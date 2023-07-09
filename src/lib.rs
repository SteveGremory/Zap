pub mod compression;
pub mod encryption;
pub mod internal;
pub mod signing;

use std::{
    fs::{self},
    io::{self, Write},
    path,
};

use aes_gcm::AeadCore;
use compression::{compress, decompress, algorithms::lz4_decoder};
use encryption::{algorithm::{aes256, aes256_r,encryption_passthrough, decryption_passthrough, chacha20poly1305, aes256cbc_openssl}};
use internal::{bind_io_constructors, convert_pw_to_key};
use signing::{signers::{signer_passthrough, verifier_passthrough}, Signer};
use walkdir::WalkDir;
use crate::compression::algorithms::lz4_encoder;

pub async fn compress_directory//<T: Signer<U>+Write+Send+'static, U: Write+Send>
(
    input_folder_path: &str,
    output_folder_path: &str,
    pass: Option<Vec<u8>>,
    //writer: impl Fn(Result<std::fs::File, std::io::Error>) -> Result<T, std::io::Error>
) -> io::Result<()> 
{
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

        std::fs::create_dir_all(current_dir)
            .expect("Failed to create all the required directories/subdirectories");
        
        let psk: Vec<u8> = match &pass {
            Some(p) => p.clone(),
            None => vec![]
        };
        // Currently each task binds it's own constructor, this is obviously
        // very inefficient but Box<dyn Fn ...> aren't thread safe
        // so one cannot pass them over thread boundaries.
        // Maybe if we add the ability to hot-swap the underlying writer so that it is created once
        // we can save initialisation and binding, but that will be later.
        
        //let w = writer(fs::File::create(output_path));

        task_list.push(
            tokio::spawn(async move {
                /*compress(
                    fs::File::open(entry_path).expect("Failed to open input file"), 
                    w
                )*/
                let i = 0;
                match i {
                    0 => compress(
                        fs::File::open(entry_path).expect("Failed to open input file"), bind_io_constructors(
                        aes256(
                            convert_pw_to_key("password".to_string(), 256).unwrap(),
                            Vec::from(b"a8d910231536".as_slice())
                        ),
                        lz4_encoder, 
                        signer_passthrough
                    )(fs::File::create(output_path))),
                    1 => compress(
                        fs::File::open(entry_path).expect("Failed to open input file"),bind_io_constructors(
                        chacha20poly1305(
                            convert_pw_to_key("password".to_string(), 256).unwrap(),
                            vec![0u8;12]
                        ),
                        lz4_encoder, 
                        signer_passthrough
                    )(fs::File::create(output_path))),
                    2 => compress(
                        fs::File::open(entry_path).expect("Failed to open input file"),bind_io_constructors(
                        aes256cbc_openssl(
                            convert_pw_to_key("password".to_string(), 256).unwrap(),
                            vec![0u8;32]
                        ),
                        lz4_encoder, 
                        signer_passthrough
                    )(fs::File::create(output_path))),
                    _ => compress(
                        fs::File::open(entry_path).expect("Failed to open input file"),bind_io_constructors(
                        encryption_passthrough(),
                        lz4_encoder, 
                        signer_passthrough
                    )(fs::File::create(output_path)))
                }
            })
        )
    }

    for val in task_list.into_iter() {
        val.await.err();
    }

    Ok(())
}

// todo: This function will alter the filename of binary files eg:
// a binary called 'someBinary' will end up as 'someBinary.'
pub async fn decompress_directory(
    input_folder_path: &str,
    output_folder_path: &str,
    pass: Option<Vec<u8>>
) -> io::Result<()>
{
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

            let psk = pass.clone();
            task_list.push(
                tokio::spawn(async move {
                    let reader = bind_io_constructors(
                        match psk {
                            Some(psk) => {
                                aes256_r(
                                    psk.clone(),
                                    Vec::from(b"a8d910231536".as_slice())
                                )
                            },
                            None => {
                                decryption_passthrough()
                            }
                        },
                        lz4_decoder, 
                        verifier_passthrough
                    );
    
                    decompress(
                        reader(
                            fs::File::open(entry_path)
                        ),
                        fs::File::create(output_path).expect("Failed to create file.")
                    )
                })
            )
        }
    }

    for val in task_list.into_iter() {
        val.await.err();
    }

    Ok(())
}
