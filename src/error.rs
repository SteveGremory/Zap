use rayon::ThreadPoolBuildError;

#[derive(Debug, thiserror::Error)]
pub enum ZapError {
    #[error("{0}")]
    NotImplemented(String),
    #[error("Generic Error: {0}")]
    Generic(String),
    #[error(transparent)]
    HashingError(HashingError),
    #[error(transparent)]
    PasswordError(PasswordError),
    #[error(transparent)]
    IOError(std::io::Error),
    #[error(transparent)]
    CompressionError(CompressionError),
    #[error(transparent)]
    DecompressionError(DecompressionError),
    #[error(transparent)]
    EncryptionError(EncryptionError),
    #[error(transparent)]
    EncryptionSecretError(EncryptionSecretError),
    #[error(transparent)]
    FailedToInitialiseLogger(log::SetLoggerError),
}

impl From<EncryptionSecretError> for ZapError {
    fn from(value: EncryptionSecretError) -> Self {
        ZapError::EncryptionSecretError(value)
    }
}

impl From<EncryptionError> for ZapError {
    fn from(value: EncryptionError) -> Self {
        ZapError::EncryptionError(value)
    }
}

impl From<CompressionError> for ZapError {
    fn from(value: CompressionError) -> Self {
        ZapError::CompressionError(value)
    }
}

impl From<DecompressionError> for ZapError {
    fn from(value: DecompressionError) -> Self {
        ZapError::DecompressionError(value)
    }
}


impl From<std::io::Error> for ZapError {
    fn from(value: std::io::Error) -> Self {
        ZapError::IOError(value)
    }
}

impl From<PasswordError> for ZapError {
    fn from(value: PasswordError) -> Self {
        ZapError::PasswordError(value)
    }
}

impl From<log::SetLoggerError> for ZapError {
    fn from(value: log::SetLoggerError) -> Self {
        ZapError::FailedToInitialiseLogger(value)
    }
}

#[derive(Debug, thiserror::Error)] 
pub enum EncryptionError
{
    #[error(transparent)]
    InitError(EncryptionSecretError)
}

#[derive(Debug, thiserror::Error)]
pub enum EncryptorInitError {
    #[error("Failed to init algorithm: {0}")]
    AlgorithmError(String),
    #[error(transparent)]
    EncryptionSecretError(EncryptionSecretError)
}

impl From<EncryptionSecretError> for EncryptionError {
    fn from(value: EncryptionSecretError) -> Self {
        EncryptionError::InitError(value)
    }
}

#[derive(Debug, thiserror::Error)] 
pub enum EncryptionSecretError
{
    #[error(transparent)]
    Password(PasswordError),
    #[error(transparent)]
    Key(EncryptionKeyError)
}

impl From<PasswordError> for EncryptionSecretError {
    fn from(value: PasswordError) -> Self {
        EncryptionSecretError::Password(value)
    }
}

impl From<EncryptionKeyError> for EncryptionSecretError {
    fn from(value: EncryptionKeyError) -> Self {
        EncryptionSecretError::Key(value)
    }
}

#[derive(Debug, thiserror::Error)] 
pub enum EncryptionKeyError
{
    #[error("Keyfile not provided")]
    KeyfileNotProvided,
    #[error("Keyfile not found: {0}")]
    FailedToFindKeyfile(String)
}


#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    #[error("Passwords do not match")]
    PasswordsDoNotMatch,
    #[error("Password is empty")]
    PasswordEmpty,
    #[error(transparent)]
    HashingError(HashingError),
    #[error(transparent)]
    InputError(InputError),
}

impl From<InputError> for PasswordError {
    fn from(value: InputError) -> Self {
        PasswordError::InputError(value)
    }
}

impl From<HashingError> for PasswordError {
    fn from(value: HashingError) -> Self {
        PasswordError::HashingError(value)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HashingError {
    #[error("UnrecognisedAlgorithm: {0}")]
    UnrecognisedAlgorithm(String),
    #[error("UnrecognisedAlgorithmLength: {0}")]
    UnrecognisedAlgorithmLength(usize)
}

#[derive(Debug, thiserror::Error)]
pub enum InputError {
    #[error("Failed to get user input: {0}")]
    UserInputFailed(std::io::Error)
}

impl From<std::io::Error> for InputError {
    fn from(value: std::io::Error) -> Self {
        InputError::UserInputFailed(value)
    }
}

#[derive(Debug, thiserror::Error)] 
pub enum CompressionError {
    #[error("Failed to build thread pool: {0}")]
    FailedToBuildThreadPool(ThreadPoolBuildError),
    #[error("Failed to walk directory: {0}")]
    FailedToWalkDirectory(walkdir::Error),
    #[error(transparent)]
    IOError(std::io::Error)
}

impl From<std::io::Error> for CompressionError {
    fn from(value: std::io::Error) -> Self {
        CompressionError::IOError(value)
    }
}

impl From<ThreadPoolBuildError> for CompressionError {
    fn from(value: ThreadPoolBuildError) -> Self {
        CompressionError::FailedToBuildThreadPool(value)
    }
}

impl From<walkdir::Error> for CompressionError {
    fn from(value: walkdir::Error) -> Self {
        CompressionError::FailedToWalkDirectory(value)
    }
}

#[derive(Debug, thiserror::Error)] 
pub enum DecompressionError {
    #[error("Failed to build thread pool: {0}")]
    FailedToBuildThreadPool(ThreadPoolBuildError),
    #[error("Failed to walk directory: {0}")]
    FailedToWalkDirectory(walkdir::Error),
    #[error(transparent)]
    IOError(std::io::Error)
}

impl From<std::io::Error> for DecompressionError {
    fn from(value: std::io::Error) -> Self {
        DecompressionError::IOError(value)
    }
}

impl From<ThreadPoolBuildError> for DecompressionError {
    fn from(value: ThreadPoolBuildError) -> Self {
        DecompressionError::FailedToBuildThreadPool(value)
    }
}

impl From<walkdir::Error> for DecompressionError {
    fn from(value: walkdir::Error) -> Self {
        DecompressionError::FailedToWalkDirectory(value)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PipelineCompressionError {
    #[error("Generic Error: {0}")]
    Generic(String),
    #[error(transparent)]
    HashingError(HashingError),
    #[error(transparent)]
    PasswordError(PasswordError),
    #[error(transparent)]
    IOError(std::io::Error),
    #[error(transparent)]
    CompressionError(CompressionError),
    #[error(transparent)]
    EncryptionError(EncryptionError),
    #[error(transparent)]
    EncryptionSecretError(EncryptionSecretError),
    #[error(transparent)]
    EncryptorInitError(EncryptorInitError),
    #[error(transparent)]
    CompressorInitError(CompressorInitError),
}

impl From<CompressorInitError> for PipelineCompressionError {
    fn from(value: CompressorInitError) -> Self {
        PipelineCompressionError::CompressorInitError(value)
    }
}

impl From<EncryptorInitError> for PipelineCompressionError {
    fn from(value: EncryptorInitError) -> Self {
        PipelineCompressionError::EncryptorInitError(value)
    }
}

impl From<EncryptionSecretError> for PipelineCompressionError {
    fn from(value: EncryptionSecretError) -> Self {
        PipelineCompressionError::EncryptionSecretError(value)
    }
}

impl From<EncryptionError> for PipelineCompressionError {
    fn from(value: EncryptionError) -> Self {
        PipelineCompressionError::EncryptionError(value)
    }
}

impl From<CompressionError> for PipelineCompressionError {
    fn from(value: CompressionError) -> Self {
        PipelineCompressionError::CompressionError(value)
    }
}

impl From<std::io::Error> for PipelineCompressionError {
    fn from(value: std::io::Error) -> Self {
        PipelineCompressionError::IOError(value)
    }
}

impl From<PasswordError> for PipelineCompressionError {
    fn from(value: PasswordError) -> Self {
        PipelineCompressionError::PasswordError(value)
    }
}

impl From<HashingError> for PipelineCompressionError {
    fn from(value: HashingError) -> Self {
        PipelineCompressionError::HashingError(value)
    }
}

impl From<ThreadPoolBuildError> for PipelineCompressionError {
    fn from(value: ThreadPoolBuildError) -> Self {
        PipelineCompressionError::CompressionError(CompressionError::FailedToBuildThreadPool(value))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PipelineDecompressionError {
    #[error("Generic Error: {0}")]
    Generic(String),
    #[error(transparent)]
    HashingError(HashingError),
    #[error(transparent)]
    PasswordError(PasswordError),
    #[error(transparent)]
    IOError(std::io::Error),
    #[error(transparent)]
    DecompressionError(DecompressionError),
    #[error(transparent)]
    EncryptionError(EncryptionError),
    #[error(transparent)]
    EncryptionSecretError(EncryptionSecretError),
    #[error(transparent)]
    DecryptorInitError(EncryptorInitError),
    #[error(transparent)]
    CompressionInitError(CompressorInitError),
}

impl From<CompressorInitError> for PipelineDecompressionError {
    fn from(value: CompressorInitError) -> Self {
        PipelineDecompressionError::CompressionInitError(value)
    }
}

impl From<EncryptorInitError> for PipelineDecompressionError {
    fn from(value: EncryptorInitError) -> Self {
        PipelineDecompressionError::DecryptorInitError(value)
    }
}

impl From<EncryptionSecretError> for PipelineDecompressionError {
    fn from(value: EncryptionSecretError) -> Self {
        PipelineDecompressionError::EncryptionSecretError(value)
    }
}

impl From<EncryptionError> for PipelineDecompressionError {
    fn from(value: EncryptionError) -> Self {
        PipelineDecompressionError::EncryptionError(value)
    }
}

impl From<DecompressionError> for PipelineDecompressionError {
    fn from(value: DecompressionError) -> Self {
        PipelineDecompressionError::DecompressionError(value)
    }
}

impl From<std::io::Error> for PipelineDecompressionError {
    fn from(value: std::io::Error) -> Self {
        PipelineDecompressionError::IOError(value)
    }
}

impl From<PasswordError> for PipelineDecompressionError {
    fn from(value: PasswordError) -> Self {
        PipelineDecompressionError::PasswordError(value)
    }
}

impl From<HashingError> for PipelineDecompressionError {
    fn from(value: HashingError) -> Self {
        PipelineDecompressionError::HashingError(value)
    }
}

impl From<ThreadPoolBuildError> for PipelineDecompressionError {
    fn from(value: ThreadPoolBuildError) -> Self {
        PipelineDecompressionError::DecompressionError(DecompressionError::FailedToBuildThreadPool(value))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PipelineBuildError {
    #[error(transparent)]
    CompressInit(CompressorInitError),
    #[error(transparent)]
    SignerInit(SignerInitError),
    #[error(transparent)]
    EncryptorInit(EncryptorInitError)
}

impl From<CompressorInitError> for PipelineBuildError {
    fn from(value: CompressorInitError) -> Self {
        PipelineBuildError::CompressInit(value)
    }
}

impl From<SignerInitError> for PipelineBuildError {
    fn from(value: SignerInitError) -> Self {
        PipelineBuildError::SignerInit(value)
    }
}

impl From<EncryptorInitError> for PipelineBuildError {
    fn from(value: EncryptorInitError) -> Self {
        PipelineBuildError::EncryptorInit(value)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CompressorInitError {

}

#[derive(Debug, thiserror::Error)]
pub enum SignerInitError {
    
}