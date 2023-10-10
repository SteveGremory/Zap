use std::{
    fs::File,
    io::{copy, Read, Write},
    path::PathBuf, backtrace,
};

use crate::{
    compression::{
        gzip::GzipAlgorithm, lz4::Lz4Algorithm, snappy::SnappyAlgorithm, Compress,
        CompressionAlgorithm, CompressionType, DecompressionAlgorithm, passthrough::PassthroughAlgorithm, Decompress,
    },
    encryption::{
        aes_gcm_256::AesGcmAlgorithm, chachapoly::ChaChaPolyAlgorithm,
        passthrough::{EncryptorPassthrough, DecryptorPassthrough}, xchachapoly::XChaChaPolyAlgorithm, DecryptionAlgorithm,
        EncryptionAlgorithm, EncryptionModule, EncryptionSecret, EncryptionType, self, DecryptionModule,
    },
    error::{PipelineBuildError, PipelineCompressionError, PipelineDecompressionError},
    signing::{
        passthrough::{SignerPassthrough, VerifierPassthrough}, Sign, SignerMethod, SigningType, VerifierMethod, Verify,
    },
};

pub struct PipeLineConfig {
    encryption: EncryptionType,
    encryption_secret: EncryptionSecret,
    compression: CompressionType,
    compression_level: flate2::Compression,
    signing: SigningType,
    source: PathBuf,
    destination: PathBuf,
}

impl PipeLineConfig {
    pub fn compress_dir(self) -> Result<(), PipelineCompressionError> {
        let mut io = File::open(&self.source)?;

        self.build_encryptor(io)
    }

    pub fn decompress_dir(self) -> Result<(), PipelineDecompressionError> {
        Ok(())
    }

    pub fn build_encryptor<T>(mut self, io: T) -> Result<(), PipelineCompressionError> 
    where
        T: Write,
    {
        let encryption_secret = self.encryption_secret.clone(); // TODO: Try to get rid of this clone...

        match encryption_secret {
            EncryptionSecret::Password(p) => match self.encryption {
                EncryptionType::XChaCha => self.build_compressor(XChaChaPolyAlgorithm::new().with_key(p).encryptor(io)?),
                EncryptionType::ChaCha => self.build_compressor(ChaChaPolyAlgorithm::new().with_key(p).encryptor(io)?),
                EncryptionType::AesGcm => self.build_compressor(AesGcmAlgorithm::new().with_key(p).encryptor(io)?),
                EncryptionType::Passthrough => self.build_compressor(EncryptorPassthrough::from(io)),
            },
            EncryptionSecret::Key(k) => {
                unimplemented!("Key encryption not yet implemented")
            }
            EncryptionSecret::None => self.build_compressor(EncryptorPassthrough::from(io)),
        }
    }

    pub fn build_compressor<T>(&self, io: T) -> Result<(), PipelineCompressionError>
    where
        T: EncryptionModule,
    {
        let compression_level = self.compression_level.clone(); // TODO: Try to get rid of this clone...

        match self.compression {
            CompressionType::Lz4 => self.build_signer(Lz4Algorithm::new().compressor(io)?),
            CompressionType::Gzip => self.build_signer(
                GzipAlgorithm::with_compression_level(compression_level).compressor(io)?,
            ),
            CompressionType::Snappy => self.build_signer(SnappyAlgorithm::new().compressor(io)?),
            CompressionType::Passthrough => self.build_signer(PassthroughAlgorithm::new().compressor(io)?),
        };

        Ok(())
    }

    pub fn build_signer<T>(&self, io: T) -> Result<(), PipelineCompressionError> 
    where
        T: Compress,
    {
        match self.signing {
            SigningType::Passthrough => {
                let pipeline = TaskPipeline::from_writer(SignerPassthrough::from(io));
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
                // TODO: Return ok
            Ok(_) => log::debug!(
                "Finished compressing '{:?}' successfully",
                self.source.display()
            ),
            // TODO: Return error instead of panicking
            Err(e) => {


                let bt = backtrace::Backtrace::capture();
                log::error!(
                    "Error while compressing '{}': {:?}",
                    self.source.display(),
                    e
                );
                log::trace!(
                    "Error while compressing '{}': {:?}",
                    self.source.display(),
                    bt
                );
                panic!();
            }
        }

        Ok(())
    }

    pub fn build_dencryptor<T>(mut self, io: T) -> Result<(), PipelineCompressionError> 
    where
        T: Read,
    {
        let encryption_secret = self.encryption_secret.clone(); // TODO: Try to get rid of this clone...

        match encryption_secret {
            EncryptionSecret::Password(p) => match self.encryption {
                EncryptionType::XChaCha => self.build_decompressor(XChaChaPolyAlgorithm::new().with_key(p).decryptor(io)?),
                EncryptionType::ChaCha => self.build_decompressor(ChaChaPolyAlgorithm::new().with_key(p).decryptor(io)?),
                EncryptionType::AesGcm => self.build_decompressor(AesGcmAlgorithm::new().with_key(p).decryptor(io)?),
                EncryptionType::Passthrough => self.build_decompressor(DecryptorPassthrough::from(io)),
            },
            EncryptionSecret::Key(k) => {
                unimplemented!("Key encryption not yet implemented")
            }
            EncryptionSecret::None => self.build_decompressor(DecryptorPassthrough::from(io)),
        }
    }

    pub fn build_decompressor<T>(&self, io: T) -> Result<(), PipelineCompressionError>
    where
        T: DecryptionModule,
    {
        let compression_level = self.compression_level.clone(); // TODO: Try to get rid of this clone...

        match self.compression {
            CompressionType::Lz4 => self.build_verifier(Lz4Algorithm::new().decompressor(io)?),
            CompressionType::Gzip => self.build_verifier(
                GzipAlgorithm::with_compression_level(compression_level).decompressor(io)?,
            ),
            CompressionType::Snappy => self.build_verifier(SnappyAlgorithm::new().decompressor(io)?),
            CompressionType::Passthrough => self.build_verifier(PassthroughAlgorithm::new().decompressor(io)?),
        };

        Ok(())
    }

    pub fn build_verifier<T>(&self, io: T) -> Result<(), PipelineCompressionError> 
    where
        T: Decompress,
    {
        match self.signing {
            SigningType::Passthrough => {
                let pipeline = TaskPipeline::from_reader(VerifierPassthrough::from(io));
                self.execute_decompression_pipeline(pipeline)
            }
        }
    }

    fn execute_decompression_pipeline<T>(&self, pipeline: T) -> Result<(), PipelineCompressionError> 
    where 
        T: DecompressionPipeline,
    {
        let mut source = File::open(&self.source)?;

        match pipeline.decompress(&mut source) {
                // TODO: Return ok
            Ok(_) => log::debug!(
                "Finished compressing '{:?}' successfully",
                self.source.display()
            ),
            // TODO: Return error instead of panicking
            Err(e) => {


                let bt = backtrace::Backtrace::capture();
                log::error!(
                    "Error while compressing '{}': {:?}",
                    self.source.display(),
                    e
                );
                log::trace!(
                    "Error while compressing '{}': {:?}",
                    self.source.display(),
                    bt
                );
                panic!();
            }
        }

        Ok(())
    }
}

impl Default for PipeLineConfig {
    fn default() -> Self {
        PipeLineConfig {
            encryption: EncryptionType::default(),
            encryption_secret: EncryptionSecret::default(),
            compression: CompressionType::default(),
            compression_level: flate2::Compression::default(),
            signing: SigningType::default(),
            source: PathBuf::default(),
            destination: PathBuf::default(),
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

pub struct TaskPipeline<T> {
    inner: T,
}

impl TaskPipeline<()> {
    pub fn builder() -> TaskPipelineBuilder<(), (), (), ()> {
        TaskPipelineBuilder::new()
    }

    pub fn from_writer<U>(io: U) -> TaskPipeline<U>
    where
        U: Write,
    {
        TaskPipeline { inner: io }
    }

    pub fn from_reader<U>(io: U) -> TaskPipeline<U>
    where
        U: Read,
    {
        TaskPipeline { inner: io }
    }
}

impl<T> CompressionPipeline for TaskPipeline<T>
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

impl<T> DecompressionPipeline for TaskPipeline<T>
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
    pub fn compression_pipeline(self) -> Result<TaskPipeline<S::Signer>, PipelineBuildError> {
        Ok(TaskPipeline {
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
    pub fn decompression_pipeline(self) -> Result<TaskPipeline<S::Verifier>, PipelineBuildError> {
        Ok(TaskPipeline {
            inner: self.signing.verifier(
                self.compression
                    .decompressor(self.encryption.decryptor(self.io)?)?,
            )?,
        })
    }
}
