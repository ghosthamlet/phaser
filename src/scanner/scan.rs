use crate::scanner::{
    HostModule,
    modules,
    Target,
    BaseModule,
    Config,
    findings,
};
use serde::{Serialize, Deserialize};
use crate::log::macros::*;
use std::fs;



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
        // for each target
        for (i, target) in targets.iter().enumerate() {
            // can ports
            let ports_module = modules::Ports{};
            let (ports_module_findings, errs) = ports_module.run(self, &target);
            match ports_module_findings {
                Some(ref finding_data) => self.targets[i].findings.push(ports_module.findings(finding_data.clone())),
                _ => {},
            }
            self.targets[i].errors.append(&mut ports_module.errs(&errs));

            // then host modules
            let host_modules = modules::get_host_modules();
            host_modules.iter().for_each(|module| {
                info!("starting module: {}", module.name());
                let (module_findings, errs) = module.run(self, &target);
                match module_findings {
                    Some(finding_data) => self.targets[i].findings.push(module.findings(finding_data)),
                    _ => {},
                }
                self.targets[i].errors.append(&mut module.errs(&errs));
                info!("module {} completed", module.name());
            });

            // and finally, for each open port of the target, ports modules
            let port_modules = modules::get_port_modules();
            match ports_module_findings {
                Some(findings::Data::Ports(ref ports)) => {
                    ports.iter().for_each(|port| {
                        port_modules.iter().for_each(|module| {
                            info!("starting module: {}", module.name());
                            let (module_findings, errs) = module.run(self, &target, &port);
                            match module_findings {
                                Some(finding_data) => self.targets[i].findings.push(module.findings(finding_data)),
                                _ => {},
                            }
                            self.targets[i].errors.append(&mut module.errs(&errs));
                            info!("module {} completed", module.name());
                        });
                    });
                },
                _ => {},
            }

        };

        let relative_path = "scan.json";
        let path = format!("{}/{}", self.config.data_folder, relative_path);

        // TODO: handle error
        fs::write(&path, serde_json::to_string_pretty(&self).expect("serializing scan to json"));
    }
}
