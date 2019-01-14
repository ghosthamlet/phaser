use serde_derive::{Serialize, Deserialize};
use std::str::FromStr;

#[derive(Debug, Deserialize, Serialize)]
pub struct Run {
    pub scanner: String,
    pub args: String,
    pub start: u64,
    pub hosts: Vec<Host>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Host {
    pub starttime: usize,
    pub endtime: usize,
    pub ports: Vec<Port>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Port {
    pub protocol: String,
    pub id: u16,
    pub service: PortService,
    pub status: PortStatus,
    pub reason: String,
    pub reason_ttl: usize,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub enum PortStatus {
    Open,
    Filtered,
    Unfiltered,
    Closed,
    OpenFiltered,
    CloseFiltered,
}

impl FromStr for PortStatus {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let s = s.trim().to_lowercase();
        match s.as_ref() {
            "open" => Ok(PortStatus::Open),
            "filtered" => Ok(PortStatus::Filtered),
            "unfiltered" => Ok(PortStatus::Unfiltered),
            "closed" => Ok(PortStatus::Closed),
            "open|filtered" => Ok(PortStatus::OpenFiltered),
            "close|filtered" => Ok(PortStatus::CloseFiltered),
            _ => Err("invalid port status".to_owned()),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PortService {
    pub name: String,
    pub method: String,
    pub conf: usize,
}
