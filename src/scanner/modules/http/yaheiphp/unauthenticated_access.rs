use crate::scanner::{
    module,
    findings,
    Scan,
    Target,
    TargetKind,
};


pub struct UnauthenticatedAccess{}

impl module::BaseModule for UnauthenticatedAccess {
    fn name(&self) -> String {
        return "http/yaheiphp/unauthenticated-access".to_string();
    }

    fn description(&self) -> String {
        return "Check for Yahei (http://www.yahei.net) Unauthenticated Access".to_string();
    }

    fn author(&self) -> String {
        return "Sylvain Kerkour <sylvain@kerkour.com>".to_string();
    }

    fn version(&self) -> String {
        return "0.1.0".to_string();
    }
}

impl module::PortModule for UnauthenticatedAccess {
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

        // TODO: also check tz_e.php
        let url = format!("{}://{}:{}/proberv.php", &protocol, &target.host, &port.id);
        let body = reqwest::get(&url)
            .expect("error fetching url for http/yaheiphp/unauthenticated-access")
            .text()
            .expect("error getting body to txt");

        if body.contains(r#"<title>Yahei-PHP"#) {
            ret = Some(findings::Data::Url(findings::Url{
                url,
            }));
        }

        return (ret, errs);
    }
}
