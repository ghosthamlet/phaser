use crate::scanner::{
    module,
    findings,
    Scan,
    Target,
};


pub struct DashboardUnauthenticatedAccess{}

impl module::BaseModule for DashboardUnauthenticatedAccess {
    fn name(&self) -> String {
        return "http/traefik/dashboard-unauthenticated-access".to_string();
    }

    fn description(&self) -> String {
        return "Check for Containous Traefik Dashboard Unauthenticated Access".to_string();
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
            .expect("error fetching url for http/traefik/dashboard-unauthenticated-access")
            .text()
            .expect("error getting body to txt");


        if (body.contains(r#"ng-app="traefik""#)
            && body.contains(r#"href="https://docs.traefik.io""#)
            && body.contains(r#"href="https://traefik.io""#))
            || body.contains(r#"fixed-top"><head><meta charset="utf-8"><title>Traefik</title><base"#) {
            ret = Some(findings::Data::Url(findings::Url{
                url,
            }));
        }

        return (ret, errs);
    }
}
