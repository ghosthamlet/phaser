use crate::scanner::{
    module,
    findings,
    Scan,
    Target,
};
use std::process::{Command};
use crate::scanner::modules::ssltls::sslyze;


pub struct Cve2014_0160{}

impl module::BaseModule for Cve2014_0160 {
    fn name(&self) -> String {
        return String::from("ssltls/cve-2014-0160");
    }

    fn description(&self) -> String {
        return String::from("Check for CVE-2014-0160 (a.k.a. heartbleed). See http://heartbleed.com for more information");
    }

    fn author(&self) -> String {
        return String::from("Sylvain Kerkour <sylvain@kerkour.com>")
    }

    fn version(&self) -> String {
        return String::from("0.1.0");
    }
}

impl module::PortModule for Cve2014_0160 {
    fn run(&self, _: &Scan, target: &Target, port: &findings::Port) -> (Option<findings::Data>, Vec<String>) {
        let mut errs = vec!();
        let mut output = String::new();
        let mut ret = None;

        if !port.https {
            return (ret, errs);
        }

        let url = format!("{}:{}", &target.host, port.id);
        match Command::new("sslyze")
            .arg("--heartbleed")
            .arg("--json_out=-")
            .arg(&url)
            .output()
            {
            Ok(sslyze_output) => output = String::from_utf8_lossy(&sslyze_output.stdout).to_string(),
            Err(err)  => errs.push(format!("error executing sslyze: {}", err)),
        };

        if !output.trim().is_empty() {
            match serde_json::from_str::<sslyze::Scan>(&output) {
                Ok(sslyze_scan) => {
                    if sslyze_scan.accepted_targets.len() != 1 {
                        errs.push(
                            format!("wrong number of sslyze accepted_targets: expected 1, got: {}", sslyze_scan.accepted_targets.len())
                        );
                        return (ret, errs);
                    }
                    if sslyze_scan.accepted_targets[0].commands_results.heartbleed.is_vulnerable_to_heartbleed {
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

#[cfg(test)]
mod tests {
    use crate::scanner::module::BaseModule;

    #[test]
    fn module_name() {
        let module = super::Cve2014_0160{};
        assert_eq!("ssltls/cve-2014-0160", module.name());
    }
}
