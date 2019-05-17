use crate::{
    scanner::{
        module,
        findings,
        ReportV1,
        Target,
        TargetKind,
        ModuleName,
    },
    error::PhaserError,
};
use serde::{Deserialize, Serialize};
use std::fs;


pub struct Takeover{}

impl module::BaseModule for Takeover {
    fn name(&self) -> ModuleName {
        return ModuleName::DomainTakeover;
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
    fn run(&self, scan: &ReportV1, target: &Target) -> Result<findings::Data, PhaserError> {
        if let TargetKind::Ip = target.kind {
            return Ok(findings::Data::None);
        };

        // parse fingerprints
        let fingerprints_path = format!("{}/takeover_fingerprints.json", &scan.config.assets_folder);
        let fingerprints_data = fs::read_to_string(fingerprints_path)?;

        let providers: Vec<Provider> = serde_json::from_str(&fingerprints_data)?;


        let body = reqwest::get(&format!("http://{}", &target.host))?
            .text()?;

        for provider in &providers {
            for fingerprint in &provider.fingerprints {
                if body.contains(fingerprint) {
                    return Ok(findings::Data::Takeover(findings::domain::Takeover{
                        service: provider.service.to_string(),
                    }));
                }
            }
        }
        return Ok(findings::Data::None);
    }
}

#[cfg(test)]
mod tests {
    use crate::scanner::module::BaseModule;

    #[test]
    fn module_name() {
        let module = super::Takeover{};
        assert_eq!("domain/takeover", module.name().to_string());
    }
}
