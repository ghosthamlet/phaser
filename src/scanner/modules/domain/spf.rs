use crate::{
    scanner::{
        module,
        findings,
        Scan,
        Target,
        TargetKind,
    },
    error::PhaserError,
};
use std::process::{Command};

pub struct Spf{}

impl module::BaseModule for Spf {
    fn name(&self) -> String {
        return String::from("domain/spf");
    }

    fn description(&self) -> String {
        return String::from("check if DNS SPF record is missing or insufficeient");
    }

    fn author(&self) -> String {
        return String::from("Sylvain Kerkour <sylvain@kerkour.com>")
    }

    fn version(&self) -> String {
        return String::from("0.1.0");
    }
}

// TODO: only if root domain
impl module::HostModule for Spf {
    fn run(&self, _: &Scan, target: &Target) -> Result<findings::Data, PhaserError> {
        let mut errs = vec!();
        let mut ret = findings::Data::None;
        let mut is_spf_record_missing = true;

        if let TargetKind::Ip = target.kind {
            return Ok(findings::Data::None);
        };

        // first retrieve TXT records
        let dig_output = Command::new("dig")
            .arg("+short")
            .arg("TXT")
            .arg(&target.host)
            .output()?;
        let txt_output = String::from_utf8_lossy(&dig_output.stdout).to_string();

        let records: Vec<String> = txt_output.split('\n')
            .map(|record| record.trim().to_string())
            .filter(|record| !record.is_empty())
            .collect();

        let resolves = if records.len() != 0 { true } else { false };

        // for each record, check if DMARC data is present
        for record in &records {
            if record.to_lowercase().contains("v=spf1") {
                is_spf_record_missing = false;
                break;
            }
        }

        if is_spf_record_missing {
            ret = findings::Data::Spf(findings::domain::Spf{
                domain: target.host.clone(),
                records,
                resolves,
            });
        }

        return Ok(ret);
    }
}

#[cfg(test)]
mod tests {
    use crate::scanner::module::BaseModule;

    #[test]
    fn module_name() {
        let module = super::Spf{};
        assert_eq!("domain/spf", module.name());
    }
}
