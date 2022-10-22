mod encryption;
mod files;

use encryption::*;
use files::*;

use argparse::{ArgumentParser, Store};
use std::path::Path;

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
            &["--combined-file"],
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
        // Create a new keypair
        let keypair: Keypair = Keypair::new();

        // write the keypair to disk
        let keypair_path = Path::new("/tmp/keypair");
        keypair.save_keypair(keypair_path.to_path_buf());

        // Create a combined file from the folder
        create_combined_file(&folder_path, &output_path, keypair);
    } else {
        // Create a keypair from the provided keys
        let keypair_path = Path::new("/tmp/keypair");
        let keypair: Keypair = Keypair::from(keypair_path.to_path_buf());

        // Recreate the file structure that was combined
        let combined_data = read_combined_file(file_path);
        recreate_files(combined_data, keypair).await;
    }
}
