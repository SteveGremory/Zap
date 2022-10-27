mod files;

use clap::Parser;

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
async fn main() {
    let args = Args::parse();
    files::directorize(&args.input, &args.output, args.decompress).await;
}
