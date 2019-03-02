use serde::{Serialize, Deserialize};
use crate::scanner::findings::{Finding, Module};
use std::net::{IpAddr};
use url::Host;
use std::str::FromStr;

#[derive(Debug, Deserialize, Serialize)]
pub struct Target {
    pub host: String,
    pub kind: TargetKind,
    pub ip_version: IpVersion,
    pub findings:  Vec<Finding>,
    pub errors: Vec<TargetError>,
    pub subdomains: Vec<Target>,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum TargetKind{
    Domain,
    Ip,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum IpVersion{
    V4,
    V6,
    None,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TargetError {
    pub module: Module,
    pub error: String,
}

// TODO: improve error type
impl FromStr for Target {
    type Err = String;

    fn from_str(target: &str) -> Result<Self, Self::Err> {
        // target is IP
        if let Ok(host) = Host::parse(target) {
            let mut kind = TargetKind::Domain;
            let mut ip_version = IpVersion::None;
            match host {
                Host::Domain(_) => {
                    if target.find('.') == None  {
                        return Err(format!("domain {} is not valid", target));
                    }
                },
                Host::Ipv4(_) => {
                    kind = TargetKind::Ip;
                    ip_version = IpVersion::V4;
                },
                Host::Ipv6(_) => {
                    kind = TargetKind::Ip;
                    ip_version = IpVersion::V6;
                },
            }

            return Ok(Target{
                host: String::from(target),
                kind: kind,
                ip_version: ip_version,
                findings:  vec!(),
                errors: vec!(),
                subdomains: vec!(),
            });
        }

        return Err(format!("{} is not a domain nor an IP address", target));
    }
}

impl From<IpAddr> for IpVersion {
    fn from(ip: IpAddr) -> Self {
        match ip {
           IpAddr::V4(_) => IpVersion::V4,
           IpAddr::V6(_) => IpVersion::V6,
        }
    }
}
