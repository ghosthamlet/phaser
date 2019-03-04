use crate::scanner::{
    module,
    findings,
    Scan,
    Target,
};


pub struct HeadDisclosure{}

impl module::BaseModule for HeadDisclosure {
    fn name(&self) -> String {
        return "http/git/head-disclosure".to_string();
    }

    fn description(&self) -> String {
        return "Check for .git/HEAD file disclosure".to_string();
    }

    fn author(&self) -> String {
        return "Sylvain Kerkour <sylvain@kerkour.com>".to_string();
    }

    fn version(&self) -> String {
        return "0.1.0".to_string();
    }
}

impl module::PortModule for HeadDisclosure {
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

        let url = format!("{}://{}:{}/.git/HEAD", &protocol, &target.host, &port.id);
        let body = reqwest::get(&url)
            .expect("error fetching url for http/git/head-disclosure")
            .text()
            .expect("error getting body to txt");


        if is_head_file(&body) {
            ret = Some(findings::Data::Url(findings::Url{
                url,
            }));
        }

        return (ret, errs);
    }
}

fn is_head_file(content: &str) -> bool {
    return Some(0) == content.to_lowercase().trim().find("ref:");
}

#[cfg(test)]
mod tests {
    use crate::scanner::module::BaseModule;

    #[test]
    fn module_name() {
        let module = super::HeadDisclosure{};
        assert_eq!("http/git/head-disclosure", module.name());
    }

    #[test]
    fn is_head_file() {
        let body = r#"ref: refs/heads/master"#;
        let body2 = r#"ref: refs/heads/heroku"#;
        let body3 = "lol lol lol ol ol< LO> OL  <tle>Index of kerkour.com</title> sdsds";

        assert_eq!(true, super::is_head_file(body));
        assert_eq!(true, super::is_head_file(body2));
        assert_eq!(false, super::is_head_file(body3));
    }
}
