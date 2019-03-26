use crate::{
    scanner::{
        module,
        findings,
        Scan,
        Target,
    },
    error::PhaserError,
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
    fn run(&self, _: &Scan, target: &Target, port: &findings::Port) -> Result<findings::Data, PhaserError> {
        if port.http || port.https {
            return Ok(findings::Data::None);
        }

        let url = format!("postgres://postgres@{}:{}", &target.host, &port.id);

        let ret = match Connection::connect(url.clone(), TlsMode::None) {
            Ok(_) => findings::Data::Url(findings::Url{url}),
            _ => findings::Data::None,
        };

        return Ok(ret);
    }
}


#[cfg(test)]
mod tests {
    use crate::scanner::module::BaseModule;

    #[test]
    fn module_name() {
        let module = super::UnauthenticatedAccess{};
        assert_eq!("postgresql/unauthenticated-access", module.name());
    }
}
