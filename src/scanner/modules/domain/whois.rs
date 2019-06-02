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
use std::fs;
use std::path::{Path};

pub struct Whois{}

impl module::BaseModule for Whois {
    fn name(&self) -> ModuleName {
        return ModuleName::DomainWhois;
    }

    fn description(&self) -> String {
        return String::from("retrieve Whois data");
    }

    fn author(&self) -> String {
        return String::from("Sylvain Kerkour <sylvain@kerkour.fr>")
    }

    fn version(&self) -> String {
        return String::from("0.1.0");
    }
}

impl module::HostModule for Whois {
    fn run(&self, scan: &ReportV1, target: &Target) -> Result<findings::ModuleResult, PhaserError> {
        if let TargetKind::Ip = target.kind {
            return Ok(findings::ModuleResult::None);
        };


        let whois_output = Command::new("whois")
            .arg(&target.host)
            .output()?;
        let output = String::from_utf8_lossy(&whois_output.stdout).to_string();

        if !output.is_empty() {
            let relative_path = "whois.txt";
            let path = Path::new(&scan.config.data_folder).join(relative_path);

            fs::write(&path, output)?;

            return Ok(findings::ModuleResult::File(findings::File{path: relative_path.to_owned()}));
        }

        return Ok(findings::ModuleResult::None);
    }
}

#[cfg(test)]
mod tests {
    use crate::scanner::module::BaseModule;

    #[test]
    fn module_name() {
        let module = super::Whois{};
        assert_eq!("domain/whois", module.name().to_string());
    }
}
