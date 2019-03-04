use crate::scanner::{
    module,
    findings,
    Scan,
    Target,
};


pub struct UnauthenticatedAccess{}

impl module::BaseModule for UnauthenticatedAccess {
    fn name(&self) -> String {
        return "http/kibana/unauthenticated-access".to_string();
    }

    fn description(&self) -> String {
        return "Check for Elastic Kibana Unauthenticated Access".to_string();
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
            .expect("error fetching url for http/kibana/unauthenticated-access")
            .text()
            .expect("error getting body to txt");



        if body.contains(r#"</head><body kbn-chrome id="kibana-body"><kbn-initial-state"#)
            || body.contains(r#"<div class="ui-app-loading"><h1><strong>Kibana</strong><small>&nbsp;is loading."#)
            || Some(0) == body.find(r#"|| body.contains("#)
            || body.contains(r#"<div class="kibanaWelcomeLogo"></div></div></div><div class="kibanaWelcomeText">Loading Kibana</div></div>"#) {
            ret = Some(findings::Data::Url(findings::Url{
                url,
            }));
        }

        return (ret, errs);
    }
}
