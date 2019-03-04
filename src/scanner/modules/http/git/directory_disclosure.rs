use crate::scanner::{
    module,
    findings,
    Scan,
    Target,
};


pub struct DirectoryDisclosure{}

impl module::BaseModule for DirectoryDisclosure {
    fn name(&self) -> String {
        return "http/git/directory-disclosure".to_string();
    }

    fn description(&self) -> String {
        return "Check for .git/ directory disclosure".to_string();
    }

    fn author(&self) -> String {
        return "Sylvain Kerkour <sylvain@kerkour.com>".to_string();
    }

    fn version(&self) -> String {
        return "0.1.0".to_string();
    }
}

impl module::PortModule for DirectoryDisclosure {
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

        let url = format!("{}://{}:{}/.git/config", &protocol, &target.host, &port.id);
        let body = reqwest::get(&url)
            .expect("error fetching url for http/git/directory-disclosure")
            .text()
            .expect("error getting body to txt");


        if is_git_directory_listing(&body) {
            ret = Some(findings::Data::Url(findings::Url{
                url,
            }));
        }

        return (ret, errs);
    }
}


fn is_git_directory_listing(file_content: &str) -> bool {
    return file_content.contains("HEAD")
        && file_content.contains("refs")
        && file_content.contains("config")
        && file_content.contains("index")
        && file_content.contains("objects");
}

#[cfg(test)]
mod tests {
    use crate::scanner::module::BaseModule;

    #[test]
    fn module_name() {
        let module = super::DirectoryDisclosure{};
        assert_eq!("http/git/directory-disclosure", module.name());
    }

    #[test]
    fn is_git_directory_listing() {
        let body = r#"COMMIT_EDITMSG
FETCH_HEAD
HEAD
ORIG_HEAD
config
description
hooks
index
info
logs
objects
refs"#;

        let body2 = "lol lol lol ol ol< LO> OL  <tle>Index of kerkour.com</title> sdsds";

        assert_eq!(true, super::is_git_directory_listing(body));
        assert_eq!(false, super::is_git_directory_listing(body2));
    }
}
