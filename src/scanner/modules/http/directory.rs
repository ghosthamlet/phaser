use crate::scanner::{
    module,
    findings,
    Scan,
    Target,
    TargetKind,
};
use std::process::{Command};
use regex::Regex;

pub struct DirectoryListing{}

impl module::BaseModule for DirectoryListing {
    fn name(&self) -> String {
        return String::from("http/directory-listing");
    }

    fn description(&self) -> String {
        return String::from("Check for enabled direstory listing, which often leak informationr");
    }

    fn author(&self) -> String {
        return String::from("Sylvain Kerkour <sylvain@kerkour.com>")
    }

    fn version(&self) -> String {
        return String::from("0.1.0");
    }
}

impl module::PortModule for DirectoryListing {
    fn run(&self, _: &Scan, target: &Target, port: &findings::Port) -> (Option<findings::Data>, Vec<String>) {
        let mut errs = vec!();
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

        let url = format!("{}://{}:{}/", &protocol, &target.host, &port.id);
        let body = reqwest::get(&url)
            .expect("error fetching url for direcotry listing")
            .text()
            .expect("error getting body to txt");

        let re = Regex::new(r"<title>Index of .*</title>").expect("compiling regexp");

        if re.is_match(&body) {
            ret = Some(findings::Data::Url(findings::Url{
                url,
            }));
        }

        return (ret, errs);
    }
}


#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_regexp() {
        let re = Regex::new(r"<title>Index of .*</title>").expect("compiling regexp");
        let body = "lol lol lol ol ol< LO> OL  <title>Index of kerkour.com</title> sdsds".to_string();
        let body2 = "lol lol lol ol ol< LO> OL  <tle>Index of kerkour.com</title> sdsds".to_string();
        let body3 = "".to_string();
        let body4 = "lol lol lol ol ol< LO> OL  <title>Index</title> sdsds".to_string();
        assert_eq!(true, re.is_match(&body));
        assert_eq!(false, re.is_match(&body2));
        assert_eq!(false, re.is_match(&body3));
        assert_eq!(false, re.is_match(&body4));
    }
}
