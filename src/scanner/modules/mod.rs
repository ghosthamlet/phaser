mod ports;

use crate::scanner::{PortModule, HostModule};

pub mod domain;
pub use ports::Ports;

pub fn get_port_modules() -> Vec<Box<dyn PortModule>> {
    return vec!(

    );
}

pub fn get_host_modules() -> Vec<Box<dyn HostModule>> {
    return vec!(
        Box::new(domain::Whois{}),
        Box::new(domain::Cname{}),
        Box::new(domain::Subdomains{}),
        Box::new(domain::Axfr{}),
        Box::new(domain::Dmarc{}),
        Box::new(domain::Spf{}),
         Box::new(domain::Takeover{}),
    );
}