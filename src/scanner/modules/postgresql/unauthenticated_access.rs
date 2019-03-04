use crate::scanner::{
    module,
    findings,
    Scan,
    Target,
};
use postgres::{Connection, TlsMode};

pub struct UnauthenticatedAccess{}

impl module::BaseModule for UnauthenticatedAccess {
    fn name(&self) -> String {
        return "postgresql/unauthenticated-access".to_string();
    }

    fn description(&self) -> String {
        return "Check for PostgreSQL Unauthenticated Access".to_string();
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
        let errs = vec!();
        let mut ret = None;

        if port.http || port.https {
            return (ret, errs);
        }

        let url = format!("postgres://postgres@{}:{}", &target.host, &port.id);

        match Connection::connect(url.clone(), TlsMode::None) {
            Ok(_) => { ret = Some(findings::Data::Url(findings::Url{url})); },
            _ =>  {},
        }

        return (ret, errs);
    }
}
