use crate::scanner::{
    module,
    findings,
    Scan,
    Target,
    TargetKind,
};
use std::process::{Command};
use std::io;

pub struct DsStore{}

impl module::BaseModule for DsStore {
    fn name(&self) -> String {
        return "http/ds-store".to_string();
    }

    fn description(&self) -> String {
        return "Check for .DS_Store file disclosure".to_string();
    }

    fn author(&self) -> String {
        return "Sylvain Kerkour <sylvain@kerkour.com>".to_string();
    }

    fn version(&self) -> String {
        return "0.1.0".to_string();
    }
}

// TODO: handle error
impl module::PortModule for DsStore {
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

        let url = format!("{}://{}:{}/.DS_Store", &protocol, &target.host, &port.id);
        let mut body = reqwest::get(&url)
            .expect("error fetching url for direcotry listing");

        let mut buf: Vec<u8> = vec!();
        body.copy_to(&mut buf);
        let signature = [0x0, 0x0, 0x0, 0x1, 0x42, 0x75, 0x64, 0x31];

        if &buf[0..8] == &signature {
            ret = Some(findings::Data::Url(findings::Url{
                url,
            }));
        }

        return (ret, errs);
    }
}
