use failure::Fail;
use std::io;

#[derive(Debug, Fail)]
pub enum PhaserError {
    #[fail(display="{:?}", 0)]
    Io(io::Error),

}


impl From<std::io::Error> for PhaserError {
    fn from(err: std::io::Error) -> Self {
        return PhaserError::Io(err);
    }
}
