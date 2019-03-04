use crate::scanner::{
    module,
    findings,
    Scan,
    Target,
};
use regex::Regex;



pub struct Cve2015_2080{}

impl module::BaseModule for Cve2015_2080 {
    fn name(&self) -> String {
        return "http/jetty/cve-2015-2080".to_string();
    }

    fn description(&self) -> String {
        return "Check for CVE-2015-2080 (a.k.a. Jetleak)".to_string();
    }

    fn author(&self) -> String {
        return "Sylvain Kerkour <sylvain@kerkour.com>".to_string();
    }

    fn version(&self) -> String {
        return "0.1.0".to_string();
    }
}

impl module::PortModule for Cve2015_2080 {
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

        let url = format!("{}://{}:{}", &protocol, &target.host, &port.id);
        let res = reqwest::get(&url)
            .expect("error fetching url for http/git/head-disclosure");

        if let Some(server) = res.headers().get("server") {
            let server = server.to_str().unwrap().to_lowercase();
            let server = server.trim();
            let re = Regex::new(r"^jetty\(9\.2\.(3|4|5|6|7|8).*\)$|^jetty\(9\.3\.0\.(m0|m1).*\)$").unwrap();

            if re.is_match(server) {
                ret = Some(findings::Data::Url(findings::Url{
                    url,
                }));
            }
        }

        return (ret, errs);
    }
}
