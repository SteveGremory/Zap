use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about,
    long_about = "Zap: Compress and/or encrypt a folder into a single file"
)]
struct Args {
    /// Input folder
    input: PathBuf,
    /// Output file
    output: PathBuf,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    println!(
        "Input folder: {}\nOutput file: {}",
        args.input.display(),
        args.output.display()
    );
}
