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
        return "http/consul/unauthenticated-access".to_string();
    }

    fn description(&self) -> String {
        return "Check for HashiCorp Consul Unauthenticated Access".to_string();
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

        let url = format!("{}://{}:{}", &protocol, &target.host, &port.id);
        let body = reqwest::get(&url)
            .expect("error fetching url for http/consul/unauthenticated-access")
            .text()
            .expect("error getting body to txt");

        if body.contains("Please enable JavaScript in your web browser to use Consul UI.")
            && body.contains("the UI on the same host as a consul instance.") {
            ret = Some(findings::Data::Url(findings::Url{
                url,
            }));
        }

        return (ret, errs);
    }
}
