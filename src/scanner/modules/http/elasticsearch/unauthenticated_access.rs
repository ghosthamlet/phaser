use crate::scanner::{
    module,
    findings,
    Scan,
    Target,
};
use serde::{Deserialize, Serialize};


pub struct UnauthenticatedAccess{}

impl module::BaseModule for UnauthenticatedAccess {
    fn name(&self) -> String {
        return "http/elasticsearch/unauthenticated-access".to_string();
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

impl module::PortModule for UnauthenticatedAccess {
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
        let info: ElasticsearchInfo = reqwest::get(&url)
            .expect("error fetching url for http/elasticsearch/unauthenticated-access")
            .json()
            .expect("error getting body to txt");

        if info.tagline.to_lowercase().contains("you know, for search") {
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
        let module = super::UnauthenticatedAccess{};
        assert_eq!("http/elasticsearch/unauthenticated-access", module.name());
    }
}
