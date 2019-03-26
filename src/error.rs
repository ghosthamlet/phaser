use failure::Fail;
use std::io;


#[derive(Debug, Fail)]
pub enum PhaserError {
    #[fail(display="Io: {:?}", 0)]
    Io(io::Error),

    #[fail(display="Postgres: {:?}", 0)]
    Postgres(postgres::Error),

    #[fail(display="Sslyze: {}", 0)]
    Sslyze(String),

    #[fail(display="SerdeJson: {}", 0)]
    SerdeJson(serde_json::Error),

    #[fail(display="Reqwest: {}", 0)]
    Reqwest(reqwest::Error),

    #[fail(display="Nmap: {}", 0)]
    Nmap(String),

    #[fail(display="SerdeXml: {}", 0)]
    SerdeXml(String), // TODO: improve

    #[fail(display="MySql: {}", 0)]
    MySql(mysql::Error),
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

impl From<serde_json::Error> for PhaserError {
    fn from(err: serde_json::Error) -> Self {
        return PhaserError::SerdeJson(err);
    }
}

impl From<serde_xml_rs::Error> for PhaserError {
    fn from(err: serde_xml_rs::Error) -> Self {
        return PhaserError::SerdeXml(err.description().to_string());
    }
}

impl From<reqwest::Error> for PhaserError {
    fn from(err: reqwest::Error) -> Self {
        return PhaserError::Reqwest(err);
    }
}


impl From<mysql::Error> for PhaserError {
    fn from(err: mysql::Error) -> Self {
        return PhaserError::MySql(err);
    }
}
