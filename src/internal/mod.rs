
use std::io::Error;

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

