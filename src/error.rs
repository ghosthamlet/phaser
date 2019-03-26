use failure::Fail;
use std::io;


#[derive(Debug, Fail)]
pub enum PhaserError {
    #[fail(display="Io: {:?}", 0)]
    Io(io::Error),

    #[fail(display="Postgres: {:?}", 0)]
    Postgres(postgres::Error),
}


impl From<std::io::Error> for PhaserError {
    fn from(err: std::io::Error) -> Self {
        return PhaserError::Io(err);
    }
}

impl From<postgres::Error> for PhaserError {
    fn from(err: postgres::Error) -> Self {
        return PhaserError::Postgres(err);
    }
}

