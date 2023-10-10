use std::{
    fs::File,
    io::{copy, Read, Write},
    path::PathBuf, sync::Arc,
};

use crate::{
    compression::{
        gzip::GzipAlgorithm, lz4::Lz4Algorithm, snappy::SnappyAlgorithm, Compress,
        CompressionAlgorithm, CompressionType, DecompressionAlgorithm, passthrough::PassthroughAlgorithm, Decompress,
    },
    encryption::{
        aes_gcm_256::AesGcmAlgorithm, chachapoly::ChaChaPolyAlgorithm,
        passthrough::{EncryptorPassthrough, DecryptorPassthrough}, xchachapoly::XChaChaPolyAlgorithm, DecryptionAlgorithm,
        EncryptionAlgorithm, EncryptionModule, EncryptionSecret, EncryptionType, DecryptionModule,
    },
    error::{PipelineBuildError, PipelineCompressionError, PipelineDecompressionError},
    signing::{
        passthrough::{SignerPassthrough, VerifierPassthrough}, Sign, SignerMethod, SigningType, VerifierMethod, Verify,
    },
};

#[derive(Default)]
pub struct ProcessingPipeline {
    encryption: Arc<EncryptionType>,
    encryption_secret: Arc<EncryptionSecret>,
    compression: Arc<CompressionType>,
    compression_level: Arc<flate2::Compression>,
    signing: Arc<SigningType>,
    source: PathBuf,
    destination: PathBuf,
}

impl ProcessingPipeline {
    pub fn new() -> ProcessingPipeline {
        ProcessingPipeline::default()
    }

    pub fn with_encryption(mut self, encryption: Arc<EncryptionType>) -> Self {
        self.encryption = encryption;
        self
    }

    pub fn with_encryption_secret(mut self, encryption_secret: Arc<EncryptionSecret>) -> Self {
        self.encryption_secret = encryption_secret;
        self
    }

    pub fn with_compression(mut self, compression: Arc<CompressionType>) -> Self {
        self.compression = compression;
        self
    }

    pub fn with_compression_level(mut self, compression_level: Arc<flate2::Compression>) -> Self {
        self.compression_level = compression_level;
        self
    }

    pub fn with_signing(mut self, signing: Arc<SigningType>) -> Self {
        self.signing = signing;
        self
    }

    pub fn with_source(mut self, source: PathBuf) -> Self {
        self.source = source;
        self
    }

    pub fn with_destination(mut self, destination: PathBuf) -> Self {
        self.destination = destination;
        self
    }

    pub fn compress_dir(self) -> Result<(), PipelineCompressionError> {
        let io = File::create(&self.destination)?;

        self.build_encryptor(io)
    }

    pub fn decompress_dir(self) -> Result<(), PipelineDecompressionError> {
        let io = File::open(&self.source)?;

        self.build_dencryptor(io)
    }

    pub fn build_encryptor<T>(self, io: T) -> Result<(), PipelineCompressionError> 
    where
        T: Write,
    {
        let encryption_secret = (*self.encryption_secret).clone(); // TODO: Try to get rid of this clone...

        match encryption_secret {
            EncryptionSecret::Password(p) => match *self.encryption {
                EncryptionType::XChaCha => self.build_compressor(XChaChaPolyAlgorithm::new().with_key(p).encryptor(io)?),
                EncryptionType::ChaCha => self.build_compressor(ChaChaPolyAlgorithm::new().with_key(p).encryptor(io)?),
                EncryptionType::AesGcm => self.build_compressor(AesGcmAlgorithm::new().with_key(p).encryptor(io)?),
                EncryptionType::Passthrough => self.build_compressor(EncryptorPassthrough::from(io)),
            },
            EncryptionSecret::Key(_) => {
                unimplemented!("Key encryption not yet implemented")
            }
            EncryptionSecret::None => self.build_compressor(EncryptorPassthrough::from(io)),
        }
    }

    pub fn build_compressor<T>(&self, io: T) -> Result<(), PipelineCompressionError>
    where
        T: EncryptionModule,
    {
        let compression_level = *self.compression_level; // TODO: Try to get rid of this copy...

        match *self.compression {
            CompressionType::Lz4 => self.build_signer(Lz4Algorithm::new().compressor(io)?),
            CompressionType::Gzip => self.build_signer(
                GzipAlgorithm::with_compression_level(compression_level).compressor(io)?,
            ),
            CompressionType::Snappy => self.build_signer(SnappyAlgorithm::new().compressor(io)?),
            CompressionType::Passthrough => self.build_signer(PassthroughAlgorithm::new().compressor(io)?),
        }
    }

    pub fn build_signer<T>(&self, io: T) -> Result<(), PipelineCompressionError> 
    where
        T: Compress,
    {
        match *self.signing {
            SigningType::Passthrough => {
                let pipeline = PipelineTask::from_writer(SignerPassthrough::from(io));
                self.execute_compression_pipeline(pipeline)
            }
        }
    }

    fn execute_compression_pipeline<T>(&self, pipeline: T) -> Result<(), PipelineCompressionError> 
    where 
        T: CompressionPipeline,
    {
        let mut source = File::open(&self.source)?;

        match pipeline.compress(&mut source) {
            Ok(_) => Ok(()),
            Err(e) => Err(e)
        }
    }

    pub fn build_dencryptor<T>(self, io: T) -> Result<(), PipelineDecompressionError> 
    where
        T: Read,
    {
        let encryption_secret = (*self.encryption_secret).clone(); // TODO: Try to get rid of this clone...

        match encryption_secret {
            EncryptionSecret::Password(p) => match *self.encryption {
                EncryptionType::XChaCha => self.build_decompressor(XChaChaPolyAlgorithm::new().with_key(p).decryptor(io)?),
                EncryptionType::ChaCha => self.build_decompressor(ChaChaPolyAlgorithm::new().with_key(p).decryptor(io)?),
                EncryptionType::AesGcm => self.build_decompressor(AesGcmAlgorithm::new().with_key(p).decryptor(io)?),
                EncryptionType::Passthrough => self.build_decompressor(DecryptorPassthrough::from(io)),
            },
            EncryptionSecret::Key(_) => {
                unimplemented!("Key encryption not yet implemented")
            }
            EncryptionSecret::None => self.build_decompressor(DecryptorPassthrough::from(io)),
        }
    }

    pub fn build_decompressor<T>(&self, io: T) -> Result<(), PipelineDecompressionError>
    where
        T: DecryptionModule,
    {
        let compression_level = *self.compression_level; // TODO: Try to get rid of this copy...

        match *self.compression {
            CompressionType::Lz4 => self.build_verifier(Lz4Algorithm::new().decompressor(io)?),
            CompressionType::Gzip => self.build_verifier(
                GzipAlgorithm::with_compression_level(compression_level).decompressor(io)?,
            ),
            CompressionType::Snappy => self.build_verifier(SnappyAlgorithm::new().decompressor(io)?),
            CompressionType::Passthrough => self.build_verifier(PassthroughAlgorithm::new().decompressor(io)?),
        }
    }

    pub fn build_verifier<T>(&self, io: T) -> Result<(), PipelineDecompressionError> 
    where
        T: Decompress,
    {
        match *self.signing {
            SigningType::Passthrough => {
                let pipeline = PipelineTask::from_reader(VerifierPassthrough::from(io));
                self.execute_decompression_pipeline(pipeline)
            }
        }
    }

    fn execute_decompression_pipeline<T>(&self, pipeline: T) -> Result<(), PipelineDecompressionError> 
    where 
        T: DecompressionPipeline,
    {
        let mut destination = File::create(&self.destination)?;

        match pipeline.decompress(&mut destination) {
            Ok(_) => Ok(()),
            Err(e) => Err(e)
        }
    }
}

pub trait CompressionPipeline {
    fn compress<F>(self, input: &mut F) -> Result<Option<Vec<u8>>, PipelineCompressionError>
    where
        F: Read;
}

pub trait DecompressionPipeline {
    fn decompress<F>(self, output: &mut F) -> Result<Option<Vec<u8>>, PipelineDecompressionError>
    where
        F: Write;
}

pub struct PipelineTask<T> {
    inner: T,
}

impl PipelineTask<()> {
    pub fn builder() -> TaskPipelineBuilder<(), (), (), ()> {
        TaskPipelineBuilder::new()
    }

    pub fn from_writer<U>(io: U) -> PipelineTask<U>
    where
        U: Write,
    {
        PipelineTask { inner: io }
    }

    pub fn from_reader<U>(io: U) -> PipelineTask<U>
    where
        U: Read,
    {
        PipelineTask { inner: io }
    }
}

impl<T> CompressionPipeline for PipelineTask<T>
where
    T: Sign,
{
    fn compress<F>(mut self, input: &mut F) -> Result<Option<Vec<u8>>, PipelineCompressionError>
    where
        F: Read,
    {
        copy(input, &mut self.inner)?;
        Ok(self.inner.finalise()?)
    }
}

impl<T> DecompressionPipeline for PipelineTask<T>
where
    T: Verify,
{
    fn decompress<F>(
        mut self,
        output: &mut F,
    ) -> Result<Option<Vec<u8>>, PipelineDecompressionError>
    where
        F: Write,
    {
        copy(&mut self.inner, output)?;
        Ok(self.inner.finalise()?)
    }
}

// TODO: Consider removing, this didn't end up being very helpful

pub struct TaskPipelineBuilder<T, E, C, S> {
    io: T,
    encryption: E,
    compression: C,
    signing: S,
}

impl TaskPipelineBuilder<(), (), (), ()> {
    pub fn new() -> Self {
        TaskPipelineBuilder {
            io: (),
            encryption: (),
            compression: (),
            signing: (),
        }
    }
}

impl Default for TaskPipelineBuilder<(), (), (), ()> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, E, C, S> TaskPipelineBuilder<T, E, C, S> {
    pub fn with_encryption<E2>(self, with: E2) -> TaskPipelineBuilder<T, E2, C, S> {
        TaskPipelineBuilder {
            io: self.io,
            encryption: with,
            compression: self.compression,
            signing: self.signing,
        }
    }

    pub fn with_compress_algorithm<C2>(self, with: C2) -> TaskPipelineBuilder<T, E, C2, S> {
        TaskPipelineBuilder {
            io: self.io,
            encryption: self.encryption,
            compression: with,
            signing: self.signing,
        }
    }

    pub fn with_signing<S2>(self, with: S2) -> TaskPipelineBuilder<T, E, C, S2> {
        TaskPipelineBuilder {
            io: self.io,
            encryption: self.encryption,
            compression: self.compression,
            signing: with,
        }
    }

    pub fn with_io<U>(self, io: U) -> TaskPipelineBuilder<U, E, C, S> {
        TaskPipelineBuilder {
            io,
            encryption: self.encryption,
            compression: self.compression,
            signing: self.signing,
        }
    }
}

impl<T, E, C, S> TaskPipelineBuilder<T, E, C, S>
where
    T: Write,
    E: EncryptionAlgorithm<T>,
    C: CompressionAlgorithm<E::Encryptor>,
    S: SignerMethod<C::Compressor>,
{
    pub fn compression_pipeline(self) -> Result<PipelineTask<S::Signer>, PipelineBuildError> {
        Ok(PipelineTask {
            inner: self.signing.signer(
                self.compression
                    .compressor(self.encryption.encryptor(self.io)?)?,
            )?,
        })
    }
}

impl<T, E, C, S> TaskPipelineBuilder<T, E, C, S>
where
    T: Read,
    E: DecryptionAlgorithm<T>,
    C: DecompressionAlgorithm<E::Decryptor>,
    S: VerifierMethod<C::Decompressor>,
{
    pub fn decompression_pipeline(self) -> Result<PipelineTask<S::Verifier>, PipelineBuildError> {
        Ok(PipelineTask {
            inner: self.signing.verifier(
                self.compression
                    .decompressor(self.encryption.decryptor(self.io)?)?,
            )?,
        })
    }
}
