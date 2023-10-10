use clap::ValueEnum;

// Consider moving
#[derive(Debug, Clone, ValueEnum)]
pub enum SecretType {
    Password,
    Key
}
