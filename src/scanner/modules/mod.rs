mod ports;

use crate::scanner::{PortModule, HostModule};

pub mod domain;
pub mod http;
pub mod postgresql;
pub mod mysql;
pub use ports::Ports;
pub mod ssltls;

pub fn get_port_modules() -> Vec<Box<dyn PortModule>> {
    return vec!(
        Box::new(http::DirectoryListing{}),
        Box::new(http::DsStore{}),
        Box::new(http::Dotenv{}),
        Box::new(postgresql::UnauthenticatedAccess{}),
        Box::new(mysql::UnauthenticatedAccess{}),
        Box::new(http::atlassian::Cve2017_9506{}),
        Box::new(http::cadvisor::UnauthenticatedAccess{}),
        Box::new(http::consul::UnauthenticatedAccess{}),
        Box::new(http::drupal::Cve2018_7600{}),
        Box::new(http::elasticsearch::UnauthenticatedAccess{}),
        Box::new(http::etcd::UnauthenticatedAccess{}),
        Box::new(http::git::ConfigDisclosure{}),
        Box::new(http::git::DirectoryDisclosure{}),
        Box::new(http::git::HeadDisclosure{}),
        Box::new(http::gitlab::OpenRegistration{}),
        Box::new(http::jetty::Cve2015_2080{}),
        Box::new(http::kibana::UnauthenticatedAccess{}),
        Box::new(http::prometheus::DashboardUnauthenticatedAccess{}),
        Box::new(http::traefik::DashboardUnauthenticatedAccess{}),
        Box::new(http::yaheiphp::UnauthenticatedAccess{}),
        Box::new(ssltls::Cve2014_0160{}),
        Box::new(ssltls::Cve2014_0224{}),
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
