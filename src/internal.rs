
use std::io::{
    Write,
    Error,
    ErrorKind
};

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

fn process_bind<T, U, V>(
    input: Result<T, Error>, 
    f1: fn(Result<T, Error>) -> Result<U, Error>, 
    f2: fn(Result<U, Error>) -> Result<V, Error>
) -> Result<V, Error> where
T: Write,
U: Write,
V: Write
{
    
    f2(f1(input))
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
Experimenting with some sort of functor to simplify optional processing

pub fn exp_process_bind<T: Write, U: Write>(
    input: Result<impl Write, Error>, 
    mut f: Vec<fn(Result<T, Error>) -> Result<U, Error>>, 
) -> Result<impl Write, Error> where
{
    match f.pop() {
        Some(func) => exp_process_bind(func(input), f),
        None => input
    }
}
*/