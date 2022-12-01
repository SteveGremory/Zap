// Internal
use super::{
    Encoder,
    Decoder
};

// External
use std::io::{
    Write,
    Read
};
use lz4_flex::frame::{
    FrameEncoder,
    FrameDecoder
};

pub fn lz4_encoder<T>(input: Result<T, std::io::Error>) -> Result<Encoder<T>, std::io::Error>
where T: Write
{
    Ok( Encoder { 
        inner: (FrameEncoder::new(input?)) 
    })
}

pub fn lz4_decoder<T>(input: Result<T, std::io::Error>) -> Result<Decoder<T>, std::io::Error>
where T: Read
{
    Ok( Decoder { 
        inner: (FrameDecoder::new(input?)) 
    })
}