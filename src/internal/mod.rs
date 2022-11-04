
use std::io::{
    Write,
    Error,
    ErrorKind
};

use openssl::encrypt;

pub fn build_writer<T, U, V, W>(
    compressor: fn(Result<T, Error>) -> Result<U, Error>,
    encryptor: fn(Result<U, Error>) -> Result<V, Error>,
    signer: fn(Result<V, Error>) -> Result<W, Error>,
) -> impl Fn(Result<T, Error>) -> Result<W, Error>
{
    move | x | signer(encryptor(compressor(x)))
}

pub fn return_if_equal<T>(a: T, b: T) -> Result<T, Error>
where T: Eq
{
    match a == b {
        true => Ok(a),
        false => Err(
            Error::new(
                ErrorKind::InvalidData, 
                "Passwords do not match."
            )
        ) 
    }
}

pub fn process_unit<T, U>(
    input: Result<T, Error>, 
    func: fn(Result<T, Error>) -> Result<U, Error>
) -> Result<U, Error>
{
    func(input)
}

pub fn bind<T, U, V>(
    f1: fn(Result<T, Error>) -> Result<U, Error>, 
    f2: fn(Result<U, Error>) -> Result<V, Error>,
) -> impl Fn(Result<T, Error>) -> Result<V, Error>
{
    
    move |x| f2(f1(x))
}


fn process_sign<T, U>(
    input: Result<T, Error>, 
    func: fn(Result<T, Error>) -> Result<(T, U), Error>
) -> Result<(T, U), Error>
where
T: Write
{
    func(input)
}

/*
Experimental infinite bind
pub fn experimental_bind<T: Write, U: Write>(
    x: Result<T, Error>,
    mut f: Vec<fn(Result<T, Error>) -> Result<U, Error>>, 
) -> impl Fn(Result<T, Error>) -> Result<U, Error>
{
    match f.pop() {
        Some(func) => move | x | func(experimental_bind(f, x)),
        None => x
    }
} */