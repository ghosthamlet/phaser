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
use std::fs;


#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Report {
    V1(ReportV1),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReportV1 {
    pub id: uuid::Uuid,
    pub scan_id: uuid::Uuid,
    pub config: ConfigV1,
    pub targets: Vec<Target>,
    pub phaser_version: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ConfigV1 {
    pub data_folder: String,
    pub assets_folder: String,
    // pub s3_client: S3Client,
}


impl ReportV1 {
    pub fn new(config: ConfigV1, id: uuid::Uuid, scan_id: uuid::Uuid, targets: Vec<Target>) -> ReportV1 {
        // fs::create_dir_all(&config.data_folder).expect("error creating scan's data folder");
        return ReportV1{
            id,
            scan_id,
            targets,
            config,
            phaser_version: info::VERSION.to_string(),
        };
    }

    pub fn run(&mut self) {
        // create direcotry
        fs::create_dir_all(&self.config.data_folder).expect("error creating report/{id} folder");

        let targets = self.targets.clone();
        // for each target
        for (i, target) in targets.iter().enumerate() {
            // can ports
            let ports_module = modules::Ports{};
            let ports_module_findings = ports_module.run(self, &target);
            let data = match &ports_module_findings {
                Ok(ref finding_data) => finding_data.clone(),
                Err(ref err) => findings::Data::Err(err.to_string()),
            };
            self.targets[i].findings.insert(ports_module.name(), ports_module.finding(data));

            // then host modules
            let host_modules = modules::get_host_modules();
            host_modules.iter().for_each(|module| {
                info!("starting module: {}", module.name());
                let data = match module.run(self, &target) {
                    Ok(finding_data) => finding_data,
                    Err(err) => findings::Data::Err(err.to_string()),
                };
                self.targets[i].findings.insert(module.name(), module.finding(data));
                info!("module {} completed", module.name());
            });

            // and finally, for each open port of the target, ports modules
            let port_modules = modules::get_port_modules();
            match ports_module_findings {
                Ok(findings::Data::Ports(ref ports)) => {
                    ports.iter().for_each(|port| {
                        port_modules.iter().for_each(|module| {
                            info!("starting module: {}", module.name());
                            let data = match module.run(self, &target, &port) {
                                Ok(finding_data) => finding_data,
                                Err(err) => findings::Data::Err(err.to_string()),
                            };
                            self.targets[i].findings.insert(module.name(), module.finding(data));
                            info!("module {} completed", module.name());
                        });
                    });
                },
                _ => {},
            }

        };

        let path = format!("{}/report.json", &self.config.data_folder);
        // TODO: handle error
        let shell = Report::V1(self.clone());
        fs::write(path, serde_json::to_string_pretty(&shell).expect("serializing scan to json"))
            .expect("error saving report.json");
    }
}
