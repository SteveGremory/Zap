
use std::io::{
    Error,
    ErrorKind
};
use rpassword::prompt_password;
use openssl::{
    hash::hash,
    hash::MessageDigest
};

pub trait Cleanup<T>
{
    fn cleanup(self) ->  Result<T, Error>;
}

pub fn bind<T, U, V>(
    a: impl Fn(Result<T, Error>) -> Result<U, Error>,
    b: impl Fn(Result<U, Error>) -> Result<V, Error>,
) -> impl Fn(Result<T, Error>) -> Result<V, Error>
{
    move | x | b(a(x))
}


pub fn bind_io_constructors<T, U, V, W>(
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

pub fn get_password_confirm(key_len: usize) -> Result<Vec<u8>, Error>
{
    convert_pw_to_key(
        return_if_equal(
            prompt_password("Enter a password for encryption: ")?, 
            prompt_password("Repeat encryption password: ")?
        )?,
        key_len
    )
}

pub fn get_password_noconf(key_len: usize) -> Result<Vec<u8>, std::io::Error>
{
    convert_pw_to_key(
        prompt_password(
            "Enter a password for encryption: "
        )?, 
        key_len
    )
}

pub fn convert_pw_to_key(pw: String, len: usize) -> Result<Vec<u8>, Error>
{
    match len {
        256 => {
            match hash(MessageDigest::sha256(), pw.as_bytes()) {
                Ok(digest) => {
                    Ok(digest.to_vec())
                },
                Err(e) => Err(
                    Error::new(
                        ErrorKind::Other,
                        format!("{}", e.to_string())
                    )
                )
            }
        },
        _ => Err(
            Error::from(
                ErrorKind::InvalidInput
            )
        )
    }
}