mod ports;

use serde::{Serialize, Deserialize};
use crate::scanner::BaseModule;

pub use ports::{Port, PortState};

#[derive(Debug, Deserialize, Serialize)]
pub struct Finding {
    pub module: Module,
    pub data: Data,
}

#[derive(Debug, Deserialize, Serialize)]
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


#[derive(Debug, Deserialize, Serialize)]
pub enum Data {
    Ports(Vec<Port>),
}
