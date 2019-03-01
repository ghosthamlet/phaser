use crate::scanner::{
    HostModule,
    modules,
    findings,
};
use serde::{Serialize, Deserialize};



#[derive(Debug, Deserialize, Serialize)]
pub struct Scan {
    pub findings: Vec<findings::Data>,
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
        let ports_module = modules::Ports{};
        let (module_findings, mut errs) = ports_module.run(self);
        match module_findings {
            Some(finding_data) => self.findings.push(finding_data),
            _ => {},
        }
        self.errors.append(&mut errs);

        println!("{:?}", self);
    }
}
