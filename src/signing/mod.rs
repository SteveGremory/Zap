pub mod signers;
pub mod passthrough;

// External
use std::io::{
    Error, Read, Write
};

use crate::{error::SignerInitError, compression::{Compress, Decompress}};

pub trait Signer<U> {
    /// Signature is the interface for any struct that 
    /// signs data.
    /// Signature will return the signature for all data
    /// written so far.
    fn signature(self) -> Result<Vec<u8>, Error>;

    fn finalise(self) -> Result<Vec<u8>, Error>;
}

pub trait Verifier<U> {
    /// Signature is the interface for any struct that 
    /// signs data.
    /// Signature will return the signature for all data
    /// written so far.
    fn signature(self) -> Result<bool, Error>;

    fn finalise(self) -> Result<bool, Error>;
}


pub struct SignerMode;
pub struct VerifierMode;

pub trait Sign: Write {
    fn finalise(self) -> Result<Option<Vec<u8>>, Error>;
}
pub trait Verify: Read {
    fn finalise(self) -> Result<Option<Vec<u8>>, Error>;
}

pub trait SignerMethod<T>
where T: Compress
{
    type Signer: Sign;

    fn signer(&self, writer: T) -> Result<Self::Signer, SignerInitError>;
}

pub trait VerifierMethod<T>
where T: Decompress
{
    type Verifier: Verify;

    fn verifier(&self, reader: T) -> Result<Self::Verifier, SignerInitError>;
}