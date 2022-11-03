
use std::io::{
    Write,
    Read,
    Error,
    copy,
    ErrorKind
};
use openssl::symm::{
    Cipher,
    encrypt
};
use std::fmt::Debug;

pub fn compress<T, U>(mut input: T, mut output: Result<U, Error>) -> Result<(), Error>
where 
T: Read,
U: Write+Debug
{
    let mut out = output?;
    let len = copy(&mut input, &mut out)?;
    dbg!(len);
    out.flush().unwrap();
    Ok(())
}

pub fn process_unit<T, U>(
    input: Result<T, Error>, 
    func: fn(Result<T, Error>) -> Result<U, Error>
) -> Result<U, Error> where 
T: Write,
U: Write 
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

struct EncryptionPassthrough<'a, T>
where T: Write
{
    cipher: Cipher,
    key: &'a [u8],
    iv: &'a [u8],
    writer: T
}

impl<T: Write> EncryptionPassthrough<'_, T> 
where T: Write
{

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match encrypt(
            self.cipher, 
            self.key, 
            Some(self.iv), 
            buf) {
            Ok(v) => self.writer.write(&v),
            Err(e) => return Err(
                Error::new(
                    ErrorKind::Interrupted, 
                    "Encryption faied."
                )
            )
        }
    }
}