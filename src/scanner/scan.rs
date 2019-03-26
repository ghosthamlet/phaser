use crate::scanner::{
    HostModule,
    modules,
    Target,
    BaseModule,
    findings,
};
use serde::{Serialize, Deserialize};
use crate::log::macros::*;
use crate::info;
use std::path::{Path};
use std::fs;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Scan {
    pub id: String,
    pub report_id: String,
    pub config: Config,
    pub targets: Vec<Target>,
    pub version: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Config {
    pub data_folder: String,
    pub assets_folder: String,
    // pub s3_client: S3Client,
}


impl Scan {
    pub fn new(config: Config, id: &str, report_id: &str, targets: Vec<Target>) -> Scan {
        // fs::create_dir_all(&config.data_folder).expect("error creating scan's data folder");
        return Scan{
            id: id.to_string(),
            report_id: report_id.to_string(),
            targets,
            config,
            version: info::VERSION.to_string(),
        };
    }

    pub fn run(&mut self) {
        let targets = self.targets.clone();
        // for each target
        for (i, target) in targets.iter().enumerate() {
            // can ports
            let ports_module = modules::Ports{};
            let ports_module_findings = ports_module.run(self, &target);
            match ports_module_findings {
                Ok(findings::Data::None) => {},
                Ok(ref finding_data) => self.targets[i].findings.push(ports_module.findings(finding_data.clone())),
                Err(err) =>  self.targets[i].errors.push(ports_module.err(err)),
            }

            // then host modules
            let host_modules = modules::get_host_modules();
            host_modules.iter().for_each(|module| {
                info!("starting module: {}", module.name());
                match module.run(self, &target) {
                    Ok(findings::Data::None) => {},
                    Ok(ref finding_data) => self.targets[i].findings.push(module.findings(finding_data.clone())),
                    Err(err) =>  self.targets[i].errors.push(module.err(err)),
                }
                info!("module {} completed", module.name());
            });

            // and finally, for each open port of the target, ports modules
            let port_modules = modules::get_port_modules();
            match ports_module_findings {
                Ok(findings::Data::Ports(ref ports)) => {
                    ports.iter().for_each(|port| {
                        port_modules.iter().for_each(|module| {
                            info!("starting module: {}", module.name());
                            match module.run(self, &target, &port) {
                                Ok(findings::Data::None) => {},
                                Ok(ref finding_data) => self.targets[i].findings.push(module.findings(finding_data.clone())),
                                Err(err) =>  self.targets[i].errors.push(module.err(err)),
                            }
                            info!("module {} completed", module.name());
                        });
                    });
                },
                _ => {},
            }

        };

        let relative_path = "scan.json";
        let path = Path::new(&self.config.data_folder).join(relative_path);
        // TODO: handle error
        fs::write(path, serde_json::to_string_pretty(&self).expect("serializing scan to json"))
            .expect("error saving scan.json");
    }
}
