use crate::phaser::module::{HostModule, FindingData};
use crate::phaser::modules::ports;
use serde::{Serialize, Deserialize};



#[derive(Debug, Deserialize, Serialize)]
pub struct Scan {
    pub findings: Vec<FindingData>,
}

impl Scan {
    pub fn new() -> Scan {
        return Scan{
            findings: vec!(),
        };
    }

    pub fn run(&self) {
        let ports_module = ports::Ports{};
        ports_module.run();
    }
}
