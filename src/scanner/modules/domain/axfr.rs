use crate::scanner::{
    module,
    findings,
    Scan,
    Target,
    TargetKind,
};
use std::process::{Command};

pub struct Axfr{}

impl module::BaseModule for Axfr {
    fn name(&self) -> String {
        return String::from("domain/axfr");
    }

    fn description(&self) -> String {
        return String::from("check if AXFR queries are enabled for each name server");
    }

    fn author(&self) -> String {
        return String::from("Sylvain Kerkour <sylvain@kerkour.com>")
    }

    fn version(&self) -> String {
        return String::from("0.1.0");
    }
}

impl module::HostModule for Axfr {
    fn run(&self, _: &Scan, target: &Target) -> (Option<findings::Data>, Vec<String>) {
        let mut errs = vec!();
        let mut ret = None;
        let mut ns_output = String::new();
        let mut data = vec!();

        match target.kind {
            TargetKind::Ip => { return (ret, errs); },
            _ => {}, // if domain, continue
        }

        // first retrieve NS servers
        match Command::new("dig")
            .arg("+short")
            .arg("NS")
            .arg(&target.host)
            .output()
            {
            Ok(dig_output) => ns_output = String::from_utf8_lossy(&dig_output.stdout).to_string(),
            Err(err)  => errs.push(format!("executing dig: {}", err)),
        };

        if ns_output.is_empty() {
            return (ret, errs);
        }

        let ns_servers: Vec<&str> = ns_output.split(',').collect();

        // for each server, try AXFR DNS query
        for ns_server in ns_servers {
            let mut output = String::new();
            match Command::new("dig")
                .arg("AXFR")
                .arg(&target.host)
                .arg(format!("@{}", ns_server))
                .output()
                {
                Ok(dig_output) => output = String::from_utf8_lossy(&dig_output.stdout).to_string(),
                Err(err)  => errs.push(format!("executing dig: {}", err)),
            };
            if output.contains("XFR") && !output.contains("transfer failed") {
                data.push(findings::domain::Axfr{
                    server: ns_server.to_string(),
                    response: output,
                });
            }
        }

        if data.len() != 0 {
            ret = Some(findings::Data::Axfr(data));
        }

        return (ret, errs);
    }
}
