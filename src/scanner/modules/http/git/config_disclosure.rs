use crate::scanner::{
    module,
    findings,
    Scan,
    Target,
};
use regex::Regex;



pub struct ConfigDisclosure{}

impl module::BaseModule for ConfigDisclosure {
    fn name(&self) -> String {
        return "http/git/config-disclosure".to_string();
    }

    fn description(&self) -> String {
        return "Check for .git/config file disclosure".to_string();
    }

    fn author(&self) -> String {
        return "Sylvain Kerkour <sylvain@kerkour.com>".to_string();
    }

    fn version(&self) -> String {
        return "0.1.0".to_string();
    }
}

impl module::PortModule for ConfigDisclosure {
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
            .expect("error fetching url for http/git/config-disclosure")
            .text()
            .expect("error getting body to txt");

        let re = Regex::new(r#"\[branch "[^"]*"\]"#).expect("compiling regexp");

        if re.is_match(&(body.trim().to_string().to_lowercase())) {
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
        let re = Regex::new(r#"\[branch "[^"]*"\]"#).expect("compiling regexp");
        let body = r#"[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
        ignorecase = true
        precomposeunicode = true
[remote "origin"]
        url = git@github.com:bloom42/phaser.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "master"]
        remote = origin
        merge = refs/heads/master"#.to_string();
        let body2 = "lol lol lol ol ol< LO> OL  <tle>Index of kerkour.com</title> sdsds".to_string();
        assert_eq!(true, re.is_match(&body));
        assert_eq!(false, re.is_match(&body2));
    }
}
