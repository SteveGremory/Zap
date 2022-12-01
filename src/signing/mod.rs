pub mod signers;

// External
use std::{
    io::{
        Error
    }
};

pub trait Signer<U> {
    /// Signature is the interface for any struct that 
    /// signs data.
    /// Signature will return the signature for all data
    /// written so far.
    fn signature(self) -> Result<Vec<u8>, Error>;

    fn cleanup(self) -> Result<Vec<u8>, Error>;
}

pub trait Verifier<U> {
    /// Signature is the interface for any struct that 
    /// signs data.
    /// Signature will return the signature for all data
    /// written so far.
    fn signature(self) -> Result<bool, Error>;

    fn cleanup(self) -> Result<bool, Error>;
}