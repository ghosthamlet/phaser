use crate::scanner::{
    module,
    findings,
    Scan,
    Target,
};


pub struct DashboardUnauthenticatedAccess{}

impl module::BaseModule for DashboardUnauthenticatedAccess {
    fn name(&self) -> String {
        return "http/prometheus/dashboard-unauthenticated-access".to_string();
    }

    fn description(&self) -> String {
        return "Check for Prometheus Dashboard Unauthenticated Access".to_string();
    }

    fn author(&self) -> String {
        return "Sylvain Kerkour <sylvain@kerkour.com>".to_string();
    }

    fn version(&self) -> String {
        return "0.1.0".to_string();
    }
}

impl module::PortModule for DashboardUnauthenticatedAccess {
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
        let body = reqwest::get(&url)
            .expect("error fetching url for http/prometheus/dashboard-unauthenticated-access")
            .text()
            .expect("error getting body to txt");



        if body.contains(r#"<title>Prometheus Time Series Collection and Processing Server</title>"#) {
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
        let module = super::DashboardUnauthenticatedAccess{};
        assert_eq!("http/prometheus/dashboard-unauthenticated-access", module.name());
    }
}
