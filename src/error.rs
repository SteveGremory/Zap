use rayon::ThreadPoolBuildError;

#[derive(Debug, thiserror::Error)]
pub enum ZapError {
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

#[derive(Debug, thiserror::Error)] 
pub enum EncryptionError
{
    #[error(transparent)]
    SetupError(EncryptionSecretError)
}

impl From<EncryptionSecretError> for EncryptionError {
    fn from(value: EncryptionSecretError) -> Self {
        EncryptionError::SetupError(value)
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
    FailedToWalkDirectory(walkdir::Error)
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
    FailedToWalkDirectory(walkdir::Error)
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