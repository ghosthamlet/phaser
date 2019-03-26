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


// TODO: error handling not found
impl module::PortModule for UnauthenticatedAccess {
    fn run(&self, _: &Scan, target: &Target, port: &findings::Port) -> Result<findings::Data, PhaserError> {
        let protocol = if port.http {
            "http"
        } else if port.https {
            "https"
        } else {
            ""
        };

        if protocol.is_empty() {
            return Ok(findings::Data::None);
        }

        // TODO: also check tz_e.php
        let url = format!("{}://{}:{}/proberv.php", &protocol, &target.host, &port.id);
        let body = reqwest::get(&url)?
            .text()?;

        if body.contains(r#"<title>Yahei-PHP"#) {
            return Ok(findings::Data::Url(findings::Url{
                url,
            }));
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
        assert_eq!("http/yaheiphp/unauthenticated-access", module.name());
    }
}
