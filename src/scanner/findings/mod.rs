mod ports;
mod file;
mod axfr;
mod dmarc;
mod takeover;

use serde::{Serialize, Deserialize};
use crate::scanner::BaseModule;

pub use ports::{Port, PortState};
pub use file::File;
pub use axfr::Axfr;
pub use dmarc::Dmarc;
pub use takeover::Takeover;

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
    Axfr(Vec<Axfr>),
    Dmarc(Dmarc),
    Takeover(Takeover),
}
