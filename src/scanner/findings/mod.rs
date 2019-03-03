mod ports;
mod file;


use serde::{Serialize, Deserialize};
use crate::scanner::BaseModule;

pub use ports::{Port, PortState};
pub use file::File;
pub mod domain;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Finding {
    pub module: Module,
    pub data: Data,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Module {
    pub name: String,
    pub version: String,
}

impl From<&BaseModule> for Module {
    fn from(module: &BaseModule) -> Module {
        return Module{
            name: module.name(),
            version: module.version(),
        };
    }
}


#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Data {
    Ports(Vec<Port>),
    File(File),
    Domain(String),
    Domains(Vec<String>),
    Axfr(Vec<domain::Axfr>),
    Dmarc(domain::Dmarc),
    Spf(domain::Spf),
    Takeover(domain::Takeover),
}
