use std::io::{Write, Read, copy};

use crate::{
    compression::{lz4::Lz4Algorithm, CompressionAlgorithm, DecompressionAlgorithm},
    encryption::{chachapoly::ChaChaPolyAlgorithm, EncryptionAlgorithm, DecryptionAlgorithm},
    error::{PipelineCompressionError, PipelineDecompressionError, PipelineBuildError},
    signing::{SignerMethod, VerifierMethod, Sign, Verify},
};

pub trait CompressionPipeline {
    fn compress<F>(self, input: &mut F) -> Result<Option<Vec<u8>>, PipelineCompressionError>
    where F: Read;
}

pub trait DecompressionPipeline {
    fn decompress<F>(self, input: &mut F) -> Result<Option<Vec<u8>>, PipelineDecompressionError>
    where F: Write;
}

pub struct TaskPipeline<T> {
    inner: T
}

impl TaskPipeline<()> {
    pub fn builder() -> TaskPipelineBuilder<(), (), (), ()> {
        TaskPipelineBuilder::new()
    }

    pub fn from_writer<U>(io: U) -> TaskPipeline<U>
    where U: Write
    {
        TaskPipeline {
            inner: io
        }
    }

    pub fn from_reader<U>(io: U) -> TaskPipeline<U>
    where U: Read
    {
        TaskPipeline {
            inner: io
        }
    }
}

impl <T> CompressionPipeline for TaskPipeline<T>
where
    T: Sign
{
    fn compress<F>(mut self, input: &mut F) -> Result<Option<Vec<u8>>, PipelineCompressionError> 
    where F: Read
    {
        copy(input, &mut self.inner)?;
        Ok(self.inner.finalise()?)
    }
}

impl <T> DecompressionPipeline for TaskPipeline<T>
where
    T: Verify
{
    fn decompress<F>(mut self, output: &mut F) -> Result<Option<Vec<u8>>, PipelineDecompressionError>
        where F: Write {
        copy(&mut self.inner, output)?;
        Ok(self.inner.finalise()?)
    }
}

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

impl <T, E, C, S> TaskPipelineBuilder<T, E, C, S>
where 
    T: Write,
    E: EncryptionAlgorithm<T>,
    C: CompressionAlgorithm<E::Encryptor>,
    S: SignerMethod<C::Compressor>
{
    //pipeline::FilePipelineBuilder<(), encryption::chachapoly::ChaChaPoly<std::fs::File, encryption::EncryptorMode>, compression::lz4::Lz4Compressor<encryption::chachapoly::ChaChaPoly<std::fs::File, encryption::EncryptorMode>>, signing::passthrough::SignerPassthrough<compression::lz4::Lz4Compressor<encryption::chachapoly::ChaChaPoly<std::fs::File, encryption::EncryptorMode>>>>

    pub fn compression_pipeline(self) -> Result<TaskPipeline<S::Signer>, PipelineBuildError>
    {
        Ok(TaskPipeline {
            inner: self.signing.signer(
                self.compression.compressor(
                    self.encryption.encryptor(self.io)?
                )?
            )?,
        })
    }
}

impl <T, E, C, S> TaskPipelineBuilder<T, E, C, S>
where 
    T: Read,
    E: DecryptionAlgorithm<T>,
    C: DecompressionAlgorithm<E::Decryptor>,
    S: VerifierMethod<C::Decompressor>
{
    pub fn decompression_pipeline(self) -> Result<TaskPipeline<S::Verifier>, PipelineBuildError>
    {
        Ok(TaskPipeline {
            inner: self.signing.verifier(
                self.compression.decompressor(
                    self.encryption.decryptor(self.io)?
                )?
            )?,
        })
    }
}

mod pipeline_test{
    use std::fs::File;

    use aes_gcm::AeadInPlace;

    use crate::{
        compression::{lz4::Lz4Algorithm, CompressionAlgorithm, DecompressionAlgorithm},
        encryption::{chachapoly::ChaChaPolyAlgorithm, EncryptionAlgorithm, DecryptionAlgorithm, passthrough::EncryptionPassthrough, aes_gcm_256::AesGcmAlgorithm, xchachapoly::XChaChaPolyAlgorithm, EncryptionModule},
        error::{PipelineCompressionError, PipelineDecompressionError, PipelineBuildError},
        signing::{SignerMethod, VerifierMethod, Sign, Verify, passthrough::{SignerPassthrough, VerifierPassthrough}}, password::get_password_noconf,
    };

    use super::{TaskPipeline, CompressionPipeline, DecompressionPipeline};

    #[test]
    fn test_enc() {
        let f = match File::create("./test.out") {
            Ok(f) => f,
            Err(e) => panic!("Error: {:?}", e),
        };

        let enc = match ChaChaPolyAlgorithm::new()
            .with_key(get_password_noconf(256).unwrap())
            .encryptor(f) {
                Ok(e) => e,
                Err(e) => panic!("Error: {:?}", e),
            };

        let comp = match Lz4Algorithm::new().compressor(enc) {
            Ok(c) => c,
            Err(e) => panic!("Error: {:?}", e),
        };

        let signer = SignerPassthrough::from(comp);

        let pipeline = TaskPipeline::from_writer(signer);

        let mut input = match File::open("test.in") {
            Ok(f) => f,
            Err(e) => panic!("Error: {:?}", e),
        };

        match pipeline.compress(&mut input) {
            Ok(_) => println!("Success!"),
            Err(e) => println!("Error: {:?}", e),
        };
    }

    #[test]
    fn test_decr() {
        let f = match File::open("./test.out") {
            Ok(f) => f,
            Err(e) => panic!("Out Error: {:?}", e),
        };
        let enc = match ChaChaPolyAlgorithm::new()
            .with_key(get_password_noconf(256).unwrap())
            .decryptor(f) {
                Ok(e) => e,
                Err(e) => panic!("Dec pt Error: {:?}", e),
            };

        let comp = match Lz4Algorithm::new().decompressor(enc) {
            Ok(c) => c,
            Err(e) => panic!("Decomp Error: {:?}", e),
        };

        let signer = VerifierPassthrough::from(comp);

        let pipeline = TaskPipeline::from_reader(signer);

        let mut output = match File::create("./decomp.out") {
            Ok(f) => f,
            Err(e) => panic!("Error: {:?}", e),
        };

        match pipeline.decompress(&mut output) {
            Ok(_) => println!("Success!"),
            Err(e) => println!("Pipeline Error: {:?}", e),
        };
    }    
}
