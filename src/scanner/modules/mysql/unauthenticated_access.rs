use crate::{
    scanner::{
        module,
        findings,
        Scan,
        Target,
    },
    error::PhaserError,
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
    fn run(&self, _: &Scan, target: &Target, port: &findings::Port) -> Result<findings::Data, PhaserError> {
        if port.http || port.https {
            return Ok(findings::Data::None);
        }

        let url = format!("mysql://root@{}:{}/", &target.host, &port.id);

        let conn = mysql::Conn::new(url.clone());
        if let Err(_) = conn {
            return Ok(findings::Data::None);
        }
        let ping_result = conn.expect("error accessing mysql connection").ping();
        if ping_result {
            return Ok(findings::Data::Url(findings::Url{url}));
        }

        return Ok(findings::Data::None);
    }
}


#[cfg(test)]
mod tests {
    use crate::scanner::module::BaseModule;

    #[test]
    fn module_name() {
        let module = super::UnauthenticatedAccess{};
        assert_eq!("mysql/unauthenticated-access", module.name());
    }
}
