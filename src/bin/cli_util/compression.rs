use clap::ValueEnum;
use zap::compression::CompressionType;



#[derive(Debug, Clone, ValueEnum)]
pub enum CompressionLevel{
    Fastest,
    Best,
    Default,
}

impl From<String> for CompressionLevel {
    fn from(s: String) -> Self {
        match s.as_str() {
            "fastest" =>  CompressionLevel::Fastest,
            "best" => CompressionLevel::Best,
            _ =>  CompressionLevel::Default,
        }
    }
}

impl Into<flate2::Compression> for CompressionLevel {
    fn into(self) -> flate2::Compression {
        match self {
            CompressionLevel::Fastest => flate2::Compression::fast(),
            CompressionLevel::Best => flate2::Compression::best(),
            CompressionLevel::Default => flate2::Compression::default(),
        }
    }
}

#[derive(Default, Debug, Clone, ValueEnum)]
pub enum BinCompressionType {
    Passthrough,
    #[default]
    Lz4,
    Gzip,
    Snappy,
}

impl From<String> for BinCompressionType {
    fn from(s: String) -> Self {
        match s.as_str() {
            "passthrough" => Self::Passthrough,
            "lz4" => Self::Lz4,
            "gzip" => Self::Gzip,
            "snappy" => Self::Snappy,
            "" => Self::default(),
            _ => Self::Passthrough,
        }
    }
}

impl From<CompressionType> for BinCompressionType {
    fn from(e: CompressionType) -> Self {
        match e {
            CompressionType::Passthrough => Self::Passthrough,
            CompressionType::Lz4 => Self::Lz4,
            CompressionType::Gzip => Self::Gzip,
            CompressionType::Snappy => Self::Snappy,
        }
    }
}

impl Into<CompressionType> for BinCompressionType {
    fn into(self) -> CompressionType {
        match self {
            BinCompressionType::Passthrough => CompressionType::Passthrough,
            BinCompressionType::Lz4 => CompressionType::Lz4,
            BinCompressionType::Gzip => CompressionType::Gzip,
            BinCompressionType::Snappy => CompressionType::Snappy,
        }
    }
}