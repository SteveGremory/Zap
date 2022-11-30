pub mod algorithms;

use crate::signing::{Signer, Verifier};

// External
use std::{
    io::{
        Error,
        Read,
        Write,
        copy
    }
};



pub fn compress<T, U, V>(mut input: T, output: Result<U, Error>) -> Result<Vec<u8>, Error>
where 
T: Read,
U: Write+Signer<V>,
V: Write
{
    let mut out = output?;
    copy(&mut input, &mut out)?;
    out.cleanup()
}

pub fn decompress<T, U, V>(input: Result<T, Error>, mut output: U) -> Result<bool, Error>
where 
T: Read+Verifier<V>,
U: Write,
V: Read
{
    let mut inp = input?;
    copy(&mut inp, &mut output)?;
    inp.cleanup()
}