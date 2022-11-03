
use std::io::{
    Write,
    Read,
    Error,
    copy,
    ErrorKind
};
use std::fs::File;
use lz4_flex::frame::FrameEncoder;
use openssl::symm::{
    Cipher,
    encrypt
};

use tokio::{
    io::{
        ReadBuf,
        prelude::*
    }
};


struct EncryptionPassthrough<'a>
{
    cipher: Cipher,
    key: &'a [u8],
    iv: &'a [u8],
    input: ReadBuf<'a>,
    output: ReadBuf<'a>,
}

impl EncryptionPassthrough<'_>
{
    fn write
}

impl Write for EncryptionPassthrough {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let enc = match encrypt(self.cipher, self.key, Some(self.iv), buf){
            Ok(v) => v,
            Err(e) => return Err(Error::new(ErrorKind::Interrupted, "Encryption faied."))
        };
        self.output.poll_write(enc).await;
    }
}