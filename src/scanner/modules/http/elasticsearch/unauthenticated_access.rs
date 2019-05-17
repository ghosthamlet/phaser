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
use serde::{Deserialize, Serialize};


pub struct UnauthenticatedAccess{}

impl module::BaseModule for UnauthenticatedAccess {
    fn name(&self) -> ModuleName {
        return ModuleName::HttpElasticsearchUnauthenticatedAccess;
    }

    fn description(&self) -> String {
        return "Check for elasticsearch Unauthenticated Access".to_string();
    }

    fn author(&self) -> String {
        return "Sylvain Kerkour <sylvain@kerkour.com>".to_string();
    }

    fn version(&self) -> String {
        return "0.1.0".to_string();
    }
}

// type ElasticsearchInfo struct {
// 	Name        string `json:"name"`
// 	ClusterName string `json:"cluster_name"`
// 	Tagline     string `json:"tagline"`
// }

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ElasticsearchInfo {
    pub name: String,
    pub cluster_name: String,
    pub tagline: String,
}

// TODO: error handling not found
impl module::PortModule for UnauthenticatedAccess {
    fn run(&self, _: &ReportV1, target: &Target, port: &findings::Port) -> Result<findings::ModuleResult, PhaserError> {
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
        let info: ElasticsearchInfo = reqwest::get(&url)?
            .json()?;

        if info.tagline.to_lowercase().contains("you know, for search") {
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
        let module = super::UnauthenticatedAccess{};
        assert_eq!("http/elasticsearch/unauthenticated-access", module.name().to_string());
    }
}
