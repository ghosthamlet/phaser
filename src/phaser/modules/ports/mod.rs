mod nmap;
use crate::phaser::module;
use std::process::{Command};


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
    fn run(&self) -> (module::FindingData, Vec<String>) {
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
            Ok(output) => println!("{}", String::from_utf8_lossy(&output.stdout)),
            Err(_)  => println!("error executing nmap"),
        };

        return (module::FindingData::Lol, vec!());
    }
}
