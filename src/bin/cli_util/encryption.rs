use clap::ValueEnum;
use zap::encryption::EncryptionType;

// Consider moving
#[derive(Debug, Default, Clone, ValueEnum)]
pub enum BinEncryptionType {
    Passthrough,
    #[default]
    XChaCha,
    AesGcm,
    ChaCha,
}

impl From<String> for BinEncryptionType {
    fn from(s: String) -> Self {
        match s.as_str() {
            "passthrough" => Self::Passthrough,
            "xchacha" => Self::XChaCha,
            "aesgcm" => Self::AesGcm,
            "chacha" => Self::ChaCha,
            "" => Self::default(),
            _ => Self::Passthrough,
        }
    }
}

impl From<EncryptionType> for BinEncryptionType {
    fn from(e: EncryptionType) -> Self {
        match e {
            EncryptionType::Passthrough => Self::Passthrough,
            EncryptionType::XChaCha => Self::XChaCha,
            EncryptionType::AesGcm => Self::AesGcm,
            EncryptionType::ChaCha => Self::ChaCha,
        }
    }
}

impl Into<EncryptionType> for BinEncryptionType {
    fn into(self) -> EncryptionType {
        match self {
            BinEncryptionType::Passthrough => EncryptionType::Passthrough,
            BinEncryptionType::XChaCha => EncryptionType::XChaCha,
            BinEncryptionType::AesGcm => EncryptionType::AesGcm,
            BinEncryptionType::ChaCha => EncryptionType::ChaCha,
        }
    }
}