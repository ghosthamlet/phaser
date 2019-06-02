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


pub struct DirectoryDisclosure{}

impl module::BaseModule for DirectoryDisclosure {
    fn name(&self) -> ModuleName {
        return ModuleName::HttpGitDirectoryDisclosure;
    }

    fn description(&self) -> String {
        return "Check for .git/ directory disclosure".to_string();
    }

    fn author(&self) -> String {
        return "Sylvain Kerkour <sylvain@kerkour.fr>".to_string();
    }

    fn version(&self) -> String {
        return "0.1.0".to_string();
    }
}

// TODO: error handling not found
impl module::PortModule for DirectoryDisclosure {
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

        let url = format!("{}://{}:{}/.git/config", &protocol, &target.host, &port.id);
        let body = reqwest::get(&url)?
            .text()?;

        if is_git_directory_listing(&body) {
            return Ok(findings::ModuleResult::Url(findings::Url{
                url,
            }));
        }

        return Ok(findings::ModuleResult::None);
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
        assert_eq!("http/git/directory-disclosure", module.name().to_string());
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

        let body2 = "lol lol lol ol ol< LO> OL  <tle>Index of kerkour.fr</title> sdsds";

        assert_eq!(true, super::is_git_directory_listing(body));
        assert_eq!(false, super::is_git_directory_listing(body2));
    }
}
