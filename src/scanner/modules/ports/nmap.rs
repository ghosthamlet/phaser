use serde::{Deserialize, Serialize, Deserializer};
// use serde_xml_rs::from_reader;
use std::default::Default;

#[derive(Debug, Deserialize, Serialize)]
pub struct Run {
    pub scanner: String,
    pub args: String,
    pub start: u64,
    pub version: String,
    pub xmloutputversion: String,

    #[serde(rename = "host", default)]
    pub hosts: Vec<Host>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Host {
    pub starttime: usize,
    pub endtime: usize,

    #[serde(rename = "hostnames", default)]
    pub hostnames: Hostnames,

    pub address: Address,

    pub ports: Ports,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct Hostnames {
    #[serde(rename = "hostname", default)]
    pub hostnames: Vec<Hostname>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct Hostname {
    pub name: Option<String>,
    #[serde(rename = "type", default)]
    pub type_: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Address {
    pub addrtype: String,
    pub addr: String,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct Ports {
    #[serde(rename = "port", default)]
    pub ports: Vec<Port>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct Port {
    pub protocol: String,
    #[serde(rename = "portid", default)]
    pub id: u16,
    pub service: Option<PortService>,

    pub state: PortState,
}

#[derive(Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct PortState {
    pub state: PortStatus,
    pub reason: String,
    pub reason_ttl: u64,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(untagged)]
pub enum PortStatus {
    Open,
    Filtered,
    Unfiltered,
    Closed,
    OpenFiltered,
    CloseFiltered,
}


impl Default for PortStatus {
    fn default() -> Self { PortStatus::Closed }
}

impl<'de> Deserialize<'de> for PortStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        use serde::de::Error;

        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "open" => Ok(PortStatus::Open),
            "filtered" => Ok(PortStatus::Filtered),
            "unfiltered" => Ok(PortStatus::Unfiltered),
            "closed" => Ok(PortStatus::Closed),
            "open|filtered" => Ok(PortStatus::OpenFiltered),
            "close|filtered" => Ok(PortStatus::CloseFiltered),
            _ =>  Err(D::Error::custom(format!("{} is an invalid port state", s))),
        }
    }
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct PortService {
    pub name: String,
    pub method: String,
    pub conf: usize,
}
