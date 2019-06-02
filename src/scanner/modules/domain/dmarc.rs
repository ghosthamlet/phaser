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
use std::process::{Command};

pub struct Dmarc{}

impl module::BaseModule for Dmarc {
    fn name(&self) -> ModuleName {
        return ModuleName::DomainDmarc;
    }

    fn description(&self) -> String {
        return String::from("check if DNS DMARC record is missing or insufficeient");
    }

    fn author(&self) -> String {
        return String::from("Sylvain Kerkour <sylvain@kerkour.fr>")
    }

    fn version(&self) -> String {
        return String::from("0.1.0");
    }
}

// TODO: only if root domain
impl module::HostModule for Dmarc {
    fn run(&self, _: &ReportV1, target: &Target) -> Result<findings::ModuleResult, PhaserError> {
        let mut is_dmarc_record_missing = true;

        if let TargetKind::Ip = target.kind {
            return Ok(findings::ModuleResult::None);
        };

        // first retrieve TXT records
        let dmarc_domain = format!("_dmarc.{}", &target.host);
        let dig_output = Command::new("dig")
            .arg("+short")
            .arg("TXT")
            .arg(&dmarc_domain)
            .output()?;
        let txt_output = String::from_utf8_lossy(&dig_output.stdout).to_string();

        let records: Vec<String> = txt_output.split('\n')
            .map(|record| record.trim().to_string())
            .filter(|record| !record.is_empty())
            .collect();

        let resolves = if records.len() != 0 { true } else { false };

        // for each record, check if DMARC data is present
        for record in &records {
            if record.to_lowercase().contains("v=dmarc1") {
                is_dmarc_record_missing = false;
                break;
            }
        }

        if is_dmarc_record_missing {
            return Ok(findings::ModuleResult::Dmarc(findings::domain::Dmarc{
                domain: dmarc_domain,
                records,
                resolves,
            }));
        }

        return Ok(findings::ModuleResult::None);
    }
}

#[cfg(test)]
mod tests {
    use crate::scanner::module::BaseModule;

    #[test]
    fn module_name() {
        let module = super::Dmarc{};
        assert_eq!("domain/dmarc", module.name().to_string());
    }
}
