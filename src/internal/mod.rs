
use std::io::{
    Error,
    ErrorKind
};
use rpassword::prompt_password;
use openssl::{
    hash::hash,
    hash::MessageDigest
};

// Cleanup is a function that signals for all nested
// writers/readers that no more will be read/written
// and to pad and dump your internal buffers however
// your implementation does so.
pub trait Cleanup<T>
{
    fn cleanup(self) ->  Result<T, Error>;
}

// This function binds the three constructors together 
// to make construction more general.
// That way we can swap out constructors and dynamically build
// a processing sequence for the comp/decomp functions use.
// 'a' is the constructor producing the inner-most struct and as such will be the
// one directly interacting with the underlying writer (file, socket, etc...).
// Therefore 'c' is the constructor which produces the struct that is interacted with
// by the calling function.
// 
// With all this considered the function is summed up as taking three constructor and
// returning a function that takes an underlying writer of type 'T'
// and returns a writer of type 'W'.
pub fn bind_io_constructors<T, U, V, W>(
    a: impl Fn(Result<T, Error>) -> Result<U, Error>,
    b: impl Fn(Result<U, Error>) -> Result<V, Error>,
    c: impl Fn(Result<V, Error>) -> Result<W, Error>,
) -> impl Fn(Result<T, Error>) -> Result<W, Error>
{
    move | x | c(b(a(x)))
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

// This will need to be reworked later as more encryption algorithms are
// brought in. May also need to be moved to 'bin'. 
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