use crate::scanner::module::{HostModule, FindingData};
use crate::scanner::modules::ports;
use serde::{Serialize, Deserialize};



#[derive(Debug, Deserialize, Serialize)]
pub struct Scan {
    pub findings: Vec<FindingData>,
    pub errors: Vec<String>,
}

impl Scan {
    pub fn new() -> Scan {
        return Scan{
            findings: vec!(),
            errors: vec!(),
        };
    }

    pub fn run(&mut self) {
        let ports_module = ports::Ports{};
        let (module_findings, mut errs) = ports_module.run(self);
        match module_findings {
            Some(finding_data) => self.findings.push(finding_data),
            _ => {},
        }
        self.errors.append(&mut errs);

        println!("{:?}", self);
    }
}
