use failure::Fail;
use std::io;

#[derive(Debug, Fail)]
pub enum PhaserError {
    #[fail(display="{:?}", 0)]
    Io(io::Error),
}
