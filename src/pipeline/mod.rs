use std::io::{Write, Read, copy};

use crate::{
    compression::{lz4::Lz4Algorithm, CompressionAlgorithm, DecompressionAlgorithm},
    encryption::{chachapoly::ChaChaPolyAlgorithm, EncryptionAlgorithm, DecryptionAlgorithm},
    error::{PipelineCompressionError, PipelineDecompressionError, PipelineBuildError},
    signing::{passthrough::SignerPassthroughMethod, SignerMethod, VerifierMethod, Sign, Verify},
};

pub trait CompressionPipeline {
    fn compress<F>(self, input: &mut F) -> Result<Option<Vec<u8>>, PipelineCompressionError>
    where F: Read;
}

pub trait DecompressionPipeline {
    fn decompress<F>(self, input: &mut F) -> Result<Option<Vec<u8>>, PipelineDecompressionError>
    where F: Write;
}

pub struct FilePipeline<T> {
    inner: T
}

impl FilePipeline<()> {
    pub fn builder() -> FilePipelineBuilder<(), (), (), ()> {
        FilePipelineBuilder::new()
    }

    pub fn from_writer<U>(io: U) -> FilePipeline<U>
    where U: Write
    {
        FilePipeline {
            inner: io
        }
    }

    pub fn from_reader<U>(io: U) -> FilePipeline<U>
    where U: Read
    {
        FilePipeline {
            inner: io
        }
    }
}

impl <T> CompressionPipeline for FilePipeline<T>
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

impl <T> DecompressionPipeline for FilePipeline<T>
where
    T: Verify
{
    fn decompress<F>(mut self, input: &mut F) -> Result<Option<Vec<u8>>, PipelineDecompressionError>
        where F: Write {
        copy(&mut self.inner, input)?;
        Ok(self.inner.finalise()?)
    }
}

pub struct FilePipelineBuilder<T, E, C, S> {
    io: T,
    encryption: E,
    compression: C,
    signing: S,
}

impl FilePipelineBuilder<(), (), (), ()> {
    pub fn new() -> Self {
        FilePipelineBuilder {
            io: (),
            encryption: (),
            compression: (),
            signing: (),
        }
    }
}

impl Default for FilePipelineBuilder<(), (), (), ()> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, E, C, S> FilePipelineBuilder<T, E, C, S> {
    pub fn with_encryption<E2>(self, with: E2) -> FilePipelineBuilder<T, E2, C, S> {
        FilePipelineBuilder {
            io: self.io,
            encryption: with,
            compression: self.compression,
            signing: self.signing,
        }
    }

    pub fn with_compress_algorithm<C2>(self, with: C2) -> FilePipelineBuilder<T, E, C2, S> {
        FilePipelineBuilder {
            io: self.io,
            encryption: self.encryption,
            compression: with,
            signing: self.signing,
        }
    }

    pub fn with_signing<S2>(self, with: S2) -> FilePipelineBuilder<T, E, C, S2> {
        FilePipelineBuilder {
            io: self.io,
            encryption: self.encryption,
            compression: self.compression,
            signing: with,
        }
    }

    pub fn with_io<U>(self, io: U) -> FilePipelineBuilder<U, E, C, S> {
        FilePipelineBuilder {
            io,
            encryption: self.encryption,
            compression: self.compression,
            signing: self.signing,
        }
    }
}

impl <T, E, C, S> FilePipelineBuilder<T, E, C, S>
where 
    T: Write,
    E: EncryptionAlgorithm<T>,
    C: CompressionAlgorithm<E::Encryptor>,
    S: SignerMethod<C::Compressor>
{
    //pipeline::FilePipelineBuilder<(), encryption::chachapoly::ChaChaPoly<std::fs::File, encryption::EncryptorMode>, compression::lz4::Lz4Compressor<encryption::chachapoly::ChaChaPoly<std::fs::File, encryption::EncryptorMode>>, signing::passthrough::SignerPassthrough<compression::lz4::Lz4Compressor<encryption::chachapoly::ChaChaPoly<std::fs::File, encryption::EncryptorMode>>>>

    pub fn compression_pipeline(self) -> Result<FilePipeline<S::Signer>, PipelineBuildError>
    {
        Ok(FilePipeline {
            inner: self.signing.signer(
                self.compression.compressor(
                    self.encryption.encryptor(self.io)?
                )?
            )?,
        })
    }
}

impl <T, E, C, S> FilePipelineBuilder<T, E, C, S>
where 
    T: Read,
    E: DecryptionAlgorithm<T>,
    C: DecompressionAlgorithm<E::Decryptor>,
    S: VerifierMethod<C::Decompressor>
{
    pub fn decompression_pipeline(self) -> Result<FilePipeline<S::Verifier>, PipelineBuildError>
    {
        Ok(FilePipeline {
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

    use crate::{
        compression::{lz4::Lz4Algorithm, CompressionAlgorithm, DecompressionAlgorithm},
        encryption::{chachapoly::ChaChaPolyAlgorithm, EncryptionAlgorithm, DecryptionAlgorithm},
        error::{PipelineCompressionError, PipelineDecompressionError, PipelineBuildError},
        signing::{passthrough::SignerPassthroughMethod, SignerMethod, VerifierMethod, Sign, Verify}, password::get_password_noconf,
    };

    use super::{FilePipeline, CompressionPipeline};

    #[test]
    fn _example_usage() {

        let mut _f = match File::create("./test.out") {
            Ok(f) => f,
            Err(e) => panic!("Error: {:?}", e),
        };
    
        let mut _enc = match ChaChaPolyAlgorithm::new()
            .with_key(get_password_noconf(256).unwrap())
            .with_nonce(vec![1u8; 12])
            .encryptor(_f){
                Ok(e) => e,
                Err(e) => panic!("Error: {:?}", e),
            };
    
        let mut _comp = match Lz4Algorithm::new().compressor(_enc) {
            Ok(c) => c,
            Err(e) => panic!("Error: {:?}", e),
        };
    
        let mut _signer = match SignerPassthroughMethod::new().signer(_comp) {
            Ok(s) => s,
            Err(e) => panic!("Error: {:?}", e),
        };
    
        let _p = FilePipeline::from_writer(_signer);
    
        let mut input = match File::open("test.in") {
            Ok(f) => f,
            Err(e) => panic!("Error: {:?}", e),
        };
    
        match _p.compress(&mut input) {
            Ok(Some(signature)) => println!("Success: {}", String::from_utf8_lossy(&signature)),
            Ok(None) => println!("Success: no signature"),
            Err(e) => println!("Error: {:?}", e),
        };

        let mut _f2 = std::fs::File::create("test.txt").unwrap();
    
        let _pipeline = FilePipeline::builder()
            .with_encryption(
                ChaChaPolyAlgorithm::new()
                    .with_key(vec![0u8; 32])
                    .with_nonce(vec![0u8; 12])
            )
            .with_compress_algorithm(
                Lz4Algorithm::new()
            )
            .with_signing(
                SignerPassthroughMethod::new()
            )
            .with_io(_f2)
            .compression_pipeline()
            .unwrap();
        //let pipeline = FilePipeline::builder()
        //    .with_encryption(enc)
        //    .with_compress_algorithm(comp)
        //    .with_signing(signer)
        //    .compression_pipeline();
    
        //let mut pipeline = Pipeline::new()
        //    .with_encryption(enc)
        //    .with_compress_algorithm(comp)
        //    .build()
        //    .unwrap();
    
        //let pipeline =
    }
    
}
