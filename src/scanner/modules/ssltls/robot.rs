use crate::{
    scanner::{
        module,
        findings,
        ReportV1,
        Target,
        ModuleName,
    },
    error::PhaserError,
};
use std::process::{Command};
use crate::scanner::modules::ssltls::sslyze;


pub struct Robot{}

impl module::BaseModule for Robot {
    fn name(&self) -> ModuleName {
        return ModuleName::SsltlsRobot;
    }

    fn description(&self) -> String {
        return "Check for the ROBOT attck. See https://robotattack.org for more information".to_string();
    }

    fn author(&self) -> String {
        return "Sylvain Kerkour <sylvain@kerkour.fr>".to_string();
    }

    fn version(&self) -> String {
        return "0.1.0".to_string();
    }
}

impl module::PortModule for Robot {
    fn run(&self, _: &ReportV1, target: &Target, port: &findings::Port) -> Result<findings::ModuleResult, PhaserError> {
        if !port.https {
            return Ok(findings::ModuleResult::None);
        }

        let url = format!("{}:{}", &target.host, port.id);
        let sslyze_output = Command::new("sslyze")
            .arg("--robot")
            .arg("--json_out=-")
            .arg(&url)
            .output()?;
        let output = String::from_utf8_lossy(&sslyze_output.stdout).to_string();

        if !output.trim().is_empty() {
            let sslyze_scan = serde_json::from_str::<sslyze::Scan>(&output)?;
            if sslyze_scan.accepted_targets.len() != 1 {
                return Err(PhaserError::Sslyze(format!("wrong number of sslyze accepted_targets: expected 1, got: {}", sslyze_scan.accepted_targets.len())));
            }
            if !sslyze_scan.accepted_targets[0].commands_results.robot.robot_result_enum.contains("NOT_VULNERABLE") {
                return Ok(findings::ModuleResult::Url(findings::Url{
                    url: format!("https://{}", url),
                }));
            }
        }

        return Ok(findings::ModuleResult::None);
    }
}


#[cfg(test)]
mod tests {
    use crate::scanner::module::BaseModule;

    #[test]
    fn module_name() {
        let module = super::Robot{};
        assert_eq!("ssltls/robot", module.name().to_string());
    }
}
