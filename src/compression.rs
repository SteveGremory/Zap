use crate::encryption::{copy_crypt, CryptMode, Keys};
use std::{fs, io};

/// Compress the input file and write it to the output file.
/// The output file is encrypted if the keys are supplied.
pub fn compress_lz4(input_file: fs::File, output_file: fs::File, keys: Option<Keys>) {
    let mut wtr = lz4_flex::frame::FrameEncoder::new(output_file);
    let mut rdr = input_file;

    if let Some(keys) = keys {
        copy_crypt(&mut rdr, &mut wtr, keys, CryptMode::Encrypt).unwrap();
    } else {
        io::copy(&mut rdr, &mut wtr).expect("I/O operation failed");
    }

    wtr.finish().unwrap();
}

/// Decompress the input file and write it to the output file.
/// The output file is encrypted if the keys are supplied.
pub fn decompress_lz4(input_file: fs::File, output_file: fs::File, keys: Option<Keys>) {
    let mut rdr = lz4_flex::frame::FrameDecoder::new(input_file);
    let mut wtr = output_file;

    if let Some(keys) = keys {
        copy_crypt(&mut rdr, &mut wtr, keys, CryptMode::Decrypt).unwrap();
    } else {
        io::copy(&mut rdr, &mut wtr).expect("I/O operation failed");
    }
}
