mod files;

use std::{
    fs::File,
    io::{self, BufWriter},
};

use clap::Parser;
use zapf::{pack_files, unpack_files};

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about,
    long_about = "Zap: Compress and/or encrypt a folder into a single file"
)]
struct Args {
    /// Input folder
    input: String,

    /// Output file
    output: String,

    /// Whether to decompress the data
    #[arg(short, long)]
    decompress: bool,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();

    if args.decompress {
        unpack_files(&args.input, "/tmp/unpacked")?;
        files::directorize("/tmp/unpacked", &args.output, args.decompress).await;
    } else {
        files::directorize(&args.input, "/tmp/stuff", args.decompress).await;

        let out_file = File::create(&args.output).expect("Could not create file");
        let mut out_writer = BufWriter::new(out_file);

        pack_files("/tmp/stuff", &mut out_writer)?;
    }

    Ok(())
}
