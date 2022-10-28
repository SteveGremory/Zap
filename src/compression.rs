use std::{
    fs,
    io::{self},
};

/// Compress the input file and write it to the output file.
/// The output file is encrypted if the keys are supplied.
pub fn compress_lz4(input_file: fs::File, output_file: fs::File) {
    let mut wtr = lz4_flex::frame::FrameEncoder::new(output_file.try_clone().unwrap());
    let mut rdr = input_file;

    io::copy(&mut rdr, &mut wtr).expect("I/O operation failed");

    wtr.finish().unwrap();
}

/// Decompress the input file and write it to the output file.
/// The output file is encrypted if the keys are supplied.
pub fn decompress_lz4(input_file: fs::File, output_file: fs::File) {
    let mut rdr = lz4_flex::frame::FrameDecoder::new(input_file);
    let mut wtr = output_file;

    io::copy(&mut rdr, &mut wtr).expect("I/O operation failed");
}
