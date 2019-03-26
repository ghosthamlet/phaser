use crate::{
    scanner::{
        module,
        findings,
        Scan,
        Target,
    },
    error::PhaserError,
};
use std::process::{Command};
use crate::scanner::modules::ssltls::sslyze;


pub struct Cve2014_0224{}

impl module::BaseModule for Cve2014_0224 {
    fn name(&self) -> String {
        return "ssltls/cve-2014-0224".to_string();
    }

    fn description(&self) -> String {
        return "Check for CVE-2014-0224 (a.k.a. CCS Injection). See http://ccsinjection.lepidum.co.jp".to_string();
    }

    fn author(&self) -> String {
        return "Sylvain Kerkour <sylvain@kerkour.com>".to_string();
    }

    fn version(&self) -> String {
        return "0.1.0".to_string();
    }
}

impl module::PortModule for Cve2014_0224 {
    fn run(&self, _: &Scan, target: &Target, port: &findings::Port) -> Result<findings::Data, PhaserError> {
        let mut errs = vec!();
        let mut ret = findings::Data::None;

        if !port.https {
            return Ok(findings::Data::None);
        }

        let url = format!("{}:{}", &target.host, port.id);
        let sslyze_output = Command::new("sslyze")
            .arg("--openssl_ccs")
            .arg("--json_out=-")
            .arg(&url)
            .output()?;
        let output = String::from_utf8_lossy(&sslyze_output.stdout).to_string();

        if !output.trim().is_empty() {
            let sslyze_scan = serde_json::from_str::<sslyze::Scan>(&output)?;
            if sslyze_scan.accepted_targets.len() != 1 {
                return Err(PhaserError::Sslyze(format!("wrong number of sslyze accepted_targets: expected 1, got: {}", sslyze_scan.accepted_targets.len())));
            }
            if sslyze_scan.accepted_targets[0].commands_results.openssl_ccs.is_vulnerable_to_ccs_injection {
                ret = findings::Data::Url(findings::Url{
                    url: format!("https://{}", url),
                });
            }
        }

        return Ok(ret);
    }
}


#[cfg(test)]
mod tests {
    use crate::scanner::module::BaseModule;

    #[test]
    fn module_name() {
        let module = super::Cve2014_0224{};
        assert_eq!("ssltls/cve-2014-0224", module.name());
    }
}
