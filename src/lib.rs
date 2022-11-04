pub mod compression;
pub mod encryption;
pub mod internal;

use std::{
    fs::{self, File},
    io::{self},
    path,
};

use compression::{Cleanup, compress, decompress};
use internal::{process_unit};
use walkdir::WalkDir;

pub async fn compress_directory<T: 'static>(
    input_folder_path: &str,
    output_folder_path: &str,
    compression_algorithm: fn(Result<fs::File, io::Error>) -> Result<T, io::Error>
) -> io::Result<()> 
where T: io::Write+Cleanup<fs::File>
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

        let func = compression_algorithm.clone();
        // Rewrite to return errors
        let compress_task = tokio::spawn(async move {
            /*internal::exp_process_bind(
                fs::File::create(output_path),
                vec!(func)
            );*/

            compress(
                fs::File::open(entry_path).expect("Failed to open input file"),
                internal::process_unit(
                    fs::File::create(output_path),
                    func
                )
            );
        });

        task_list.push(compress_task);
    }

    for val in task_list.into_iter() {
        val.await.err();
    }

    Ok(())
}

pub async fn decompress_directory<T: 'static>(
    input_folder_path: &str,
    output_folder_path: &str,
    decompression_algorithm: fn(Result<File, io::Error>) -> Result<T, io::Error>
) -> io::Result<()> where T: io::Read+Cleanup<fs::File>
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

            let func = decompression_algorithm.clone();

            let decompress_task = tokio::spawn(async move {
                decompress(
                    process_unit(
                        fs::File::open(entry_path),
                        func
                    ), 
                    fs::File::create(output_path).expect("Failed to create file.")
                );
            });

            task_list.push(decompress_task);
        }
    }

    for val in task_list.into_iter() {
        val.await.err();
    }

    Ok(())
}
