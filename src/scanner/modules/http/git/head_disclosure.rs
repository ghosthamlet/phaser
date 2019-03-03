use crate::scanner::{
    module,
    findings,
    Scan,
    Target,
    TargetKind,
};
use regex::Regex;



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

        let url = format!("{}://{}:{}/.git/HEAD", &protocol, &target.host, &port.id);
        let body = reqwest::get(&url)
            .expect("error fetching url for http/git/head-disclosure")
            .text()
            .expect("error getting body to txt");


        if let Some(0) = body.to_lowercase().trim().find("ref:") {
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
