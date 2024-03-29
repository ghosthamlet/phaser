use crate::{
    scanner::{
        module,
        findings,
        ReportV1,
        Target,
        ModuleName,
    },
    error::PhaserError,
};


pub struct DashboardUnauthenticatedAccess{}

impl module::BaseModule for DashboardUnauthenticatedAccess {
    fn name(&self) -> ModuleName {
        return ModuleName::HttpTraefikDashboardUnauthenticatedAccess;
    }

    fn description(&self) -> String {
        return "Check for Containous Traefik Dashboard Unauthenticated Access".to_string();
    }

    fn author(&self) -> String {
        return "Sylvain Kerkour <sylvain@kerkour.fr>".to_string();
    }

    fn version(&self) -> String {
        return "0.1.0".to_string();
    }
}

// TODO: error handling not found
impl module::PortModule for DashboardUnauthenticatedAccess {
    fn run(&self, _: &ReportV1, target: &Target, port: &findings::Port) ->  Result<findings::ModuleResult, PhaserError> {
        let protocol = if port.http {
            "http"
        } else if port.https {
            "https"
        } else {
            ""
        };

        if protocol.is_empty() {
            return Ok(findings::ModuleResult::None);
        }

        let url = format!("{}://{}:{}", &protocol, &target.host, &port.id);
        let body = reqwest::get(&url)?
            .text()?;


        if (body.contains(r#"ng-app="traefik""#)
            && body.contains(r#"href="https://docs.traefik.io""#)
            && body.contains(r#"href="https://traefik.io""#))
            || body.contains(r#"fixed-top"><head><meta charset="utf-8"><title>Traefik</title><base"#) {
            return Ok(findings::ModuleResult::Url(findings::Url{
                url,
            }));
        }

        return Ok(findings::ModuleResult::None);
    }
}


#[cfg(test)]
mod tests {
    use crate::scanner::module::BaseModule;

    #[test]
    fn module_name() {
        let module = super::DashboardUnauthenticatedAccess{};
        assert_eq!("http/traefik/dashboard-unauthenticated-access", module.name().to_string());
    }
}
