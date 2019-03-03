use crate::scanner::{
    module,
    findings,
    Scan,
    Target,
    TargetKind,
};
use std::process::{Command};
use serde::{Deserialize, Serialize};
use std::fs;
use serde_json::Result;


pub struct Takeover{}

impl module::BaseModule for Takeover {
    fn name(&self) -> String {
        return "domain/dmarc".to_string();
    }

    fn description(&self) -> String {
        return "Check subdomain for takeover".to_string();
    }

    fn author(&self) -> String {
        return "Sylvain Kerkour <sylvain@kerkour.com>".to_string();
    }

    fn version(&self) -> String {
        return "0.1.0".to_string();
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Provider {
    pub service: String,
    #[serde(rename = "cname")]
    pub cnames: Vec<String>,
    #[serde(rename = "fingerprint")]
    pub fingerprints: Vec<String>,
    pub nxdomain: bool,
}


impl module::HostModule for Takeover {
    fn run(&self, scan: &Scan, target: &Target) -> (Option<findings::Data>, Vec<String>) {
        let mut errs = vec!();
        let mut ret = None;

        match target.kind {
            TargetKind::Ip => { return (ret, errs); },
            _ => {}, // if domain, continue
        }

        // parse fingerprints
        let fingerprints_path = format!("{}/takeover_fingerprints.json", &scan.config.assets_folder);
        let fingerprints_data = fs::read_to_string(fingerprints_path)
            .expect("Something went wrong reading the fingerprints file");

        let providers: Vec<Provider> = serde_json::from_str(&fingerprints_data)
            .expect("error parsing providers fingerprints");


        let body = reqwest::get(&format!("http://{}", &target.host))
        .expect("error fetching url for takeover")
        .text()
        .expect("error getting body to txt");

        'outer: for provider in &providers {
            for fingerprint in &provider.fingerprints {
                if body.contains(fingerprint) {
                    ret = Some(findings::Data::Takeover(findings::Takeover{
                        service: provider.service.to_string(),
                    }));
                    break 'outer;
                }
            }
        }
        return (ret, errs);
    }
}
