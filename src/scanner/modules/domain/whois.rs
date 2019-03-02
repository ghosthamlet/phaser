use crate::scanner::{
    module,
    findings,
    Scan,
    Target,
    TargetKind,
};
use std::process::{Command};
use std::fs;

pub struct Whois{}

impl module::BaseModule for Whois {
    fn name(&self) -> String {
        return String::from("domain/whois");
    }

    fn description(&self) -> String {
        return String::from("retrieve Whois data");
    }

    fn author(&self) -> String {
        return String::from("Sylvain Kerkour <sylvain@kerkour.com>")
    }

    fn version(&self) -> String {
        return String::from("0.1.0");
    }
}

impl module::HostModule for Whois {
    fn run(&self, scan: &Scan, target: &Target) -> (Option<findings::Data>, Vec<String>) {
        let mut errs = vec!();
        let mut output = String::new();
        let mut ret = None;

        match target.kind {
            TargetKind::Ip => { return (ret, errs); },
            _ => {}, // if domain, continue
        }

        match Command::new("whois")
            .arg(&target.host)
            .output()
            {
            Ok(whois_output) => output = String::from_utf8_lossy(&whois_output.stdout).to_string(),
            Err(err)  => errs.push(format!("executing whois: {}", err)),
        };

        if !output.is_empty() {
            let relative_path = "whois.txt";
            let path = format!("{}/{}", scan.config.data_folder, relative_path);

            match fs::write(&path, output) {
                Ok(_) => {
                    ret = Some(findings::Data::File(findings::File{path: relative_path.to_owned()}));
                },
                Err(err) => errs.push(format!("creating whois.txt: {}", err)),
            };
        }

        return (ret, errs);
    }
}
