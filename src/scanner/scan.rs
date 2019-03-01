use crate::scanner::{
    HostModule,
    modules,
    findings,
    Target,
    IpVersion,
    TargetKind,
    TargetError,
    BaseModule,
};
use serde::{Serialize, Deserialize};



#[derive(Debug, Deserialize, Serialize)]
pub struct Scan {
    pub targets: Vec<Target>,
}

impl Scan {
    pub fn new() -> Scan {
        return Scan{
            targets: vec!(Target{
                host: String::from("127.0.0.1"),
                kind: TargetKind::Ip,
                ip_version: IpVersion::V4,
                findings:  vec!(),
                errors: vec!(),
                subdomains: vec!(),
            }),
        };
    }

    pub fn run(&mut self) {
        let ports_module = modules::Ports{};
        let (module_findings, errs) = ports_module.run(self, &self.targets[0]);
        match module_findings {
            Some(finding_data) => self.targets[0].findings.push(data_to_finding(&ports_module, finding_data)),
            _ => {},
        }
        self.targets[0].errors.append(&mut errs_to_modules_errs(&ports_module, &errs));

        println!("{:?}", self);
    }
}

fn data_to_finding(module: &BaseModule, data: findings::Data) -> findings::Finding {
    return findings::Finding{
        module: findings::Module::from(module),
        data,
    };
}

fn errs_to_modules_errs(module: &BaseModule, errs: &[String]) -> Vec<TargetError> {
    return errs.iter().map(|err| TargetError{
        module: findings::Module::from(module),
        error: err.clone(),
    }).collect();
}
