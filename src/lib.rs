mod compression;

use std::{
    fs,
    io::{self},
    path,
};

use compression::{compress_lz4, decompress_lz4};
use walkdir::WalkDir;

pub async fn compress_directory(
    input_folder_path: &str,
    output_folder_path: &str,
) -> io::Result<()> {
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

        let compress_task = tokio::spawn(async {
            let input_file = fs::File::open(entry_path).expect("Failed to open input file");
            let output_file = fs::File::create(output_path).expect("Failed to create file");
            compress_lz4(input_file, output_file);
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
) -> io::Result<()> {
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

            let decompress_task = tokio::spawn(async {
                let input_file = fs::File::open(entry_path).unwrap();
                let output_file = fs::File::create(output_path).expect("Failed to create file.");
                decompress_lz4(input_file, output_file);
            });

            task_list.push(decompress_task);
        }
    }

    for val in task_list.into_iter() {
        val.await.err();
    }

    Ok(())
}
