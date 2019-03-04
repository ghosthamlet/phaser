use crate::scanner::{
    module,
    findings,
    Scan,
    Target,
};
use std::process::{Command};
use serde_xml_rs::from_reader;
use std::time::Duration;
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
    fn run(&self, _: &Scan, target: &Target, port: &findings::Port) -> (Option<findings::Data>, Vec<String>) {
        let mut errs = vec!();
        let mut output = String::new();
        let mut ret = None;

        let url = format!("{}:{}", &target.host, port.id);
        match Command::new("sslyze")
            .arg("--openssl_ccs")
            .arg("--json_out=-")
            .arg(&url)
            .output()
            {
            Ok(sslyze_output) => output = String::from_utf8_lossy(&sslyze_output.stdout).to_string(),
            Err(err)  => errs.push(format!("error executing sslyze: {}", err)),
        };

        if !output.trim().is_empty() {
            match from_reader::<_, sslyze::Scan>(output.as_bytes()) {
                Ok(sslyze_scan) => {
                    if sslyze_scan.accepted_targets.len() != 1 {
                        errs.push(
                            format!("wrong number of sslyze accepted_targets: expected 1, got: {}", sslyze_scan.accepted_targets.len())
                        );
                        return (ret, errs);
                    }
                    if sslyze_scan.accepted_targets[0].commands_results.openssl_ccs.is_vulnerable_to_ccs_injection {
                        ret = Some(findings::Data::Url(findings::Url{
                            url: format!("https://{}", url),
                        }));
                    }
                },
                Err(err) =>  errs.push(format!("error parsing sslyze result: {}", err)),
            }
        }

        return (ret, errs);
    }
}
