use crate::scanner::{
    module,
    findings,
    Scan,
    Target,
};

pub struct UnauthenticatedAccess{}

impl module::BaseModule for UnauthenticatedAccess {
    fn name(&self) -> String {
        return "mysql/unauthenticated-access".to_string();
    }

    fn description(&self) -> String {
        return "Check for MySQL Unauthenticated Access".to_string();
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

        if port.http || port.https {
            return (ret, errs);
        }

        let url = format!("mysql://root@{}:{}/", &target.host, &port.id);

        let conn = mysql::Conn::new(url.clone());
        match conn {
            Ok(_) => {}, // do nothing, continue
            _ =>  { return (ret, errs); },
        }
        let ping_result = conn.expect("error accessing mysql connection").ping();
        if ping_result {
            ret = Some(findings::Data::Url(findings::Url{url}));
        }

        return (ret, errs);
    }
}
