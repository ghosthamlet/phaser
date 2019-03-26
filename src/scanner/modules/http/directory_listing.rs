use crate::{
    scanner::{
        module,
        findings,
        Scan,
        Target,
    },
    error::PhaserError,
};
use regex::Regex;

pub struct DirectoryListing{}

impl module::BaseModule for DirectoryListing {
    fn name(&self) -> String {
        return "http/directory-listing".to_string();
    }

    fn description(&self) -> String {
        return "Check for enabled directory listing, which often leak informationr".to_string();
    }

    fn author(&self) -> String {
        return "Sylvain Kerkour <sylvain@kerkour.com>".to_string();
    }

    fn version(&self) -> String {
        return "0.1.0".to_string();
    }
}

// TODO: error handling not found
impl module::PortModule for DirectoryListing {
    fn run(&self, _: &Scan, target: &Target, port: &findings::Port) -> Result<findings::Data, PhaserError> {
        let protocol = if port.http {
            "http"
        } else if port.https {
            "https"
        } else {
            ""
        };

        if protocol == "" {
            return Ok(findings::Data::None);
        }

        let url = format!("{}://{}:{}/", &protocol, &target.host, &port.id);
        let body = reqwest::get(&url)?
            .text()?;

        if is_directory_listing(&body) {
            return Ok(findings::Data::Url(findings::Url{
                url,
            }));
        }

        return Ok(findings::Data::None);
    }
}

fn is_directory_listing(file_content: &str) -> bool {
    let re = Regex::new(r"<title>Index of .*</title>").expect("compiling http/directory-listing regexp");
    return re.is_match(file_content);
}


#[cfg(test)]
mod tests {
    use crate::scanner::module::BaseModule;

    #[test]
    fn module_name() {
        let module = super::DirectoryListing{};
        assert_eq!("http/directory-listing", module.name());
    }

    #[test]
    fn is_directory_listing() {
        let body = "lol lol lol ol ol< LO> OL  <title>Index of kerkour.com</title> sdsds";
        let body2 = "lol lol lol ol ol< LO> OL  <tle>Index of kerkour.com</title> sdsds";
        let body3 = "";
        let body4 = "lol lol lol ol ol< LO> OL  <title>Index</title> sdsds";

        assert_eq!(true, super::is_directory_listing(&body));
        assert_eq!(false, super::is_directory_listing(&body2));
        assert_eq!(false, super::is_directory_listing(&body3));
        assert_eq!(false, super::is_directory_listing(&body4));
    }
}
