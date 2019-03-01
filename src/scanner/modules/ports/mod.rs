mod nmap;


use crate::scanner::module;
use crate::scanner::findings;
use crate::scanner::scan::Scan;
use crate::scanner::module::FindingData;
use std::process::{Command};
use serde_xml_rs::from_reader;
use nmap::{Run, Port, PortStatus};


pub struct Ports{}

impl module::BaseModule for Ports {
    fn name() -> String {
        return String::from("ports");
    }

    fn description() -> String {
        return String::from("scan ports");
    }

    fn author() -> String {
        return String::from("Sylvain Kerkour <sylvain@kerkour.com>")
    }

    fn version() -> String {
        return String::from("0.1.0");
    }
}

impl module::HostModule for Ports {
    fn run(&self, scan: &Scan) -> (Option<module::FindingData>, Vec<String>) {
        let mut errs = vec!();
        let mut output = String::new();
        let mut ret = None;

        match Command::new("nmap")
            .arg("-p")
            .arg("8080,5432,443,8081,90")
            .arg("-oX")
            .arg("-")
            .arg("127.0.0.1")
            .arg("-dd")
            .arg("--host-timeout")
            .arg("2m")
            .output()
            {
            Ok(nmap_output) => output = String::from_utf8_lossy(&nmap_output.stdout).to_string(),
            Err(err)  => errs.push(format!("error executing nmap: {}", err)),
        };

        if !output.is_empty() {
            match from_reader::<_, Run>(output.as_bytes()) {
                Ok(run) => {
                    let mut ports = vec!();
                    if run.hosts.len() == 1 {
                        let nmap_ports = run.hosts[0].ports.ports.iter()
                            .filter(|port| port.state.state == PortStatus::Open).collect::<Vec<&Port>>();
                        for nmap_port in &nmap_ports {
                            // TODO: scan for http/https
                            ports.push(findings::Port{
                                id: nmap_port.id,
                                state: findings::PortState::Open,
                                http: false,
                                https: false,
                            });
                        }
                        ret = Some(FindingData::Ports(ports));
                    } else {
                        errs.push(format!("wrong number of nmap hosts: expected 1, got: {}", run.hosts.len()))
                    }
                },
                Err(err) =>  errs.push(format!("error executing nmap: {}", err)),
            }
        }

        return (ret, errs);
    }
}
