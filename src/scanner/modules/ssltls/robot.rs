use crate::scanner::{
    module,
    findings,
    Scan,
    Target,
};
use std::process::{Command};
use crate::scanner::modules::ssltls::sslyze;


pub struct Robot{}

impl module::BaseModule for Robot {
    fn name(&self) -> String {
        return "ssltls/robot".to_string();
    }

    fn description(&self) -> String {
        return "Check for the ROBOT attck. See https://robotattack.org for more information".to_string();
    }

    fn author(&self) -> String {
        return "Sylvain Kerkour <sylvain@kerkour.com>".to_string();
    }

    fn version(&self) -> String {
        return "0.1.0".to_string();
    }
}

impl module::PortModule for Robot {
    fn run(&self, _: &Scan, target: &Target, port: &findings::Port) -> (Option<findings::Data>, Vec<String>) {
        let mut errs = vec!();
        let mut output = String::new();
        let mut ret = None;

        if !port.https {
            return (ret, errs);
        }

        let url = format!("{}:{}", &target.host, port.id);
        match Command::new("sslyze")
            .arg("--robot")
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
                    if !sslyze_scan.accepted_targets[0].commands_results.robot.robot_result_enum.contains("NOT_VULNERABLE") {
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
