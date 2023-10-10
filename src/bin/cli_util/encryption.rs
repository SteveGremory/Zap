use clap::ValueEnum;

// Consider moving
#[derive(Debug, Clone, ValueEnum)]
pub enum EncryptionType {
    Password,
    Key
}