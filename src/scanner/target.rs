use serde::{Serialize, Deserialize};
use crate::scanner::findings::{Finding, Module};

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
