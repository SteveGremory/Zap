
use std::io::{
    Error,
    ErrorKind
};


pub fn build_writer<T, U, V, W>(
    encryptor: impl Fn(Result<T, Error>) -> Result<U, Error>,
    compressor: impl Fn(Result<U, Error>) -> Result<V, Error>,
    signer: impl Fn(Result<V, Error>) -> Result<W, Error>,
) -> impl Fn(Result<T, Error>) -> Result<W, Error>
{
    move | x | signer(compressor(encryptor(x)))
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