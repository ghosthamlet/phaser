use crate::scanner::{
    module,
    findings,
    Scan,
    Target,
    TargetKind,
};
use regex::Regex;



pub struct OpenRegistration{}

impl module::BaseModule for OpenRegistration {
    fn name(&self) -> String {
        return "http/gitlab/open-registration".to_string();
    }

    fn description(&self) -> String {
        return "Check if the gitlab instance is open to registrations".to_string();
    }

    fn author(&self) -> String {
        return "Sylvain Kerkour <sylvain@kerkour.com>".to_string();
    }

    fn version(&self) -> String {
        return "0.1.0".to_string();
    }
}

impl module::PortModule for OpenRegistration {
    fn run(&self, _: &Scan, target: &Target, port: &findings::Port) -> (Option<findings::Data>, Vec<String>) {
        let mut errs = vec!();
        let mut ret = None;

        let protocol = if port.http {
            "http"
        } else if port.https {
            "https"
        } else {
            ""
        };

        if protocol == "" {
            return (ret, errs);
        }

        let url = format!("{}://{}:{}/.git/HEAD", &protocol, &target.host, &port.id);
        let body = reqwest::get(&url)
            .expect("error fetching url for http/git/head-disclosure")
            .text()
            .expect("error getting body to txt");


        if body.to_lowercase().contains("ref:") && body.contains("Register") {
            ret = Some(findings::Data::Url(findings::Url{
                url,
            }));
        }

        return (ret, errs);
    }
}
