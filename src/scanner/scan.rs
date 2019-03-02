use crate::scanner::{
    HostModule,
    modules,
    Target,
    BaseModule,
    Config,
};
use serde::{Serialize, Deserialize};



#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Scan {
    pub config: Config,
    pub targets: Vec<Target>,
}

impl Scan {
    pub fn new(config: Config, targets: Vec<Target>) -> Scan {
        return Scan{
            targets,
            config,
        };
    }

    pub fn run(&mut self) {
        let targets = self.targets.clone();
        for (i, target) in targets.iter().enumerate() {
            let ports_module = modules::Ports{};
            let (module_findings, errs) = ports_module.run(self, &target);
            match module_findings {
                Some(finding_data) => self.targets[i].findings.push(ports_module.findings(finding_data)),
                _ => {},
            }
            self.targets[i].errors.append(&mut ports_module.errs(&errs));

            let host_modules = modules::get_host_modules();
            host_modules.iter().for_each(|module| {
                let (module_findings, errs) = module.run(self, &target);
                match module_findings {
                    Some(finding_data) => self.targets[i].findings.push(module.findings(finding_data)),
                    _ => {},
                }
                self.targets[i].errors.append(&mut module.errs(&errs));
            });

            let _ = modules::get_port_modules();
        };


        println!("{:?}", self);
    }
}
