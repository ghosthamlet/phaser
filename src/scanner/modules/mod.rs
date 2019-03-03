mod ports;

use crate::scanner::{PortModule, HostModule};

pub mod domain;
pub mod http;
pub use ports::Ports;

pub fn get_port_modules() -> Vec<Box<dyn PortModule>> {
    return vec!(
        Box::new(http::DirectoryListing{}),
        Box::new(http::DsStore{}),
        Box::new(http::Dotenv{}),
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
